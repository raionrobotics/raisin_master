#!/usr/bin/env python3

import base64
import cv2
import numpy as np
import math
from mimetypes import guess_type
import asyncio
from typing import Optional, Tuple, Dict, Any, List
import os
from dotenv import load_dotenv
from openai import OpenAI
import requests

def _load_api_env():
    """Find the .env holding OPENAI_API_KEY / BING_API_KEY.

    Upstream hardcoded the Docker path /home/user/colcon_ws/..., which does not
    exist outside that container. Search the plausible locations instead and let
    an already-exported OPENAI_API_KEY win.
    """
    candidates = []
    if os.environ.get('REASONNAV_ENV'):
        candidates.append(os.environ['REASONNAV_ENV'])
    try:
        from ament_index_python.packages import get_package_share_directory
        candidates.append(
            os.path.join(get_package_share_directory('mm_dev'), 'config', '.env'))
    except Exception:
        pass
    # Source tree (survives rebuilds; where the README tells you to put it).
    candidates.append(os.path.join(
        os.path.expanduser('~'),
        'tips_ws/src/ReasonNav/src/mm_dev/config/.env'))
    # Alongside this file, for a plain source checkout.
    candidates.append(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', 'config', '.env'))

    for path in candidates:
        if path and os.path.isfile(path):
            load_dotenv(path, override=False)
            return path
    load_dotenv(override=False)  # fall back to a .env near the cwd
    return None


_API_ENV_PATH = _load_api_env()

SYSTEM_PROMPT = """
You are ChatGPT, a large language model trained by OpenAI.
Follow the user's instructions carefully.
Respond concisely, informatively, and helpfully.
If you're unsure about an answer, say so.
You have strong reasoning capabilities.
"""

VLM_TIMEOUT_S = float(os.environ.get('REASONNAV_VLM_TIMEOUT', '20'))
VLM_RETRIES = int(os.environ.get('REASONNAV_VLM_RETRIES', '1'))


class VLMClient:
    def __init__(self, api_key = None, model:str = "gpt-4o"):
        # Resolved here, not as a default argument: a default is evaluated at
        # import time, which loses any key exported after this module loads.
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Put it in "
                "src/ReasonNav/src/mm_dev/config/.env (OPENAI_API_KEY=sk-...), "
                "point REASONNAV_ENV at an .env file, or export it.")
        self.model = model
        # A timeout and a retry budget, because this client sits in the
        # navigation loop's critical path: the loop logs its keypoints, calls
        # here to choose the next landmark, and cannot do anything else until
        # the answer comes back. Left at the SDK default of ten minutes, one
        # stalled request freezes navigation completely -- the map timer and
        # the OCR timer keep running on their own threads, so from outside it
        # looks like the system is alive and simply refusing to pick a goal.
        self.client = OpenAI(api_key=self.api_key,
                             timeout=VLM_TIMEOUT_S, max_retries=VLM_RETRIES)
        # Probe the key, but do not die on it. Ablation modes 3/4 pick a
        # landmark without any VLM call, so the node is still fully useful for
        # mapping when the account is out of credit or rate limited -- letting
        # this probe raise would stop vlm_nav from starting at all.
        try:
            self.client.chat.completions.create(
                model=self.model,
                messages=[{'role': 'system', 'content': 'You are a helpful assistant.'}])
        except Exception as e:
            print(f'[vlm] API probe failed ({type(e).__name__}: {str(e)[:120]}). '
                  'Continuing; any VLM query will fail until this is resolved.')

        # for web search
        self.bing_api_key = os.getenv("BING_API_KEY")
        self.endpoint = "https://api.bing.microsoft.com/v7.0/search"

        print(f"VLMClient initialized with model: {self.model}")
        
    def images_text_query_vlm(self, images: List[np.ndarray], prompt:str) -> Optional[str]:
        """
        Process multiple images with the VLM
        
        Args:
            images: List of CV2 images (numpy arrays)
            prompt: Text prompt to send with images
            
        Returns:
            result: VLM response or None if failed
        """
        image_data_urls = [self._image_to_data_url(image) for image in images]
        result = self._call_openai_api_multi(image_data_urls, prompt)
        return result
    
    def image_text_query_vlm(self, image: np.ndarray, prompt:str) -> Optional[str]:
        """
        For backward compatibility - process a single image
        """
        return self.images_text_query_vlm([image], prompt)
    
    def text_query_vlm(self, input_prompt):
        prompt = [
            { 'role':'system', 'content': "You are a helpful assistant." },
            {'role':'user','content': [
                {'type':'text','text': input_prompt},
            ]
            }
        ]
        response = self.client.chat.completions.create(model=self.model, messages=prompt, max_completion_tokens=1000)
        return response.choices[0].message.content
    
    def search(self, query):
        # request
        params = {"q": query, "mkt": "en-US"}
        headers = {"Ocp-Apim-Subscription-Key": self.bing_api_key}

        response = requests.get(self.endpoint, headers=headers, params=params)
        response.raise_for_status()

        # Parse the response
        search_results = response.json()

        # if 'webPages' in search_results:
        #     results = search_results['webPages']['value']
        #     for idx, result in enumerate(results[:5]):  # Adjust the number as needed
        #         print(f"Result {idx + 1}:")
        #         print(f"Name: {result['name']}")
        #         print(f"URL: {result['url']}")
        #         print(f"Snippet: {result['snippet']}\n")

        prompt = f"""Analyze these Bing search results and return the best answer to the user request. 
        Return the shortest possible answer (e.g. if asked for room number return: Building Room#). 
        
        User request: {query}
        Bing results: {search_results}
        """
        vlm_result = self.text_query_vlm(prompt)
        return vlm_result
    
    def _image_to_data_url(self, image: np.ndarray) -> str:
        """
        Convert image to data URL format
        
        Args:
            image: CV2 image (numpy array)
            
        Returns:
            data_url: Image in data URL format
        """
        # Convert numpy array to data URL
        _, buffer = cv2.imencode('.jpg', image)
        base64_encoded = base64.b64encode(buffer).decode('utf-8')
        return f"data:image/jpeg;base64,{base64_encoded}"
    
    def _call_openai_api(self, image_data_url: str, prompt:str) -> Optional[str]:
        """
        Call OpenAI API with a single image (for backward compatibility)
        """
        return self._call_openai_api_multi([image_data_url], prompt)
    
    def _call_openai_api_multi(self, image_data_urls: List[str], prompt:str) -> Optional[str]:
        """
        Call OpenAI API with multiple images
        
        Args:
            image_data_urls: List of images in data URL format
            prompt: Text prompt to accompany the images
            
        Returns:
            text: VLM response or None if failed
        """
        # Prepare the image prompts
        img_prompts = [{'type': 'image_url', 'image_url': {'url': url}} for url in image_data_urls]
        
        # Create the full prompt
        prompt_messages = [
            # {SYSTEM_PROMPT} would be a one-element set, not the prompt string.
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': [
                {'type': 'text', 'text': prompt},
                *img_prompts
            ]}
        ]
        
        # Call the API
        response = self.client.chat.completions.create(
            model=self.model, 
            messages=prompt_messages, 
            max_completion_tokens=1000
        )
        
        # Extract and return the text
        if response.choices and len(response.choices) > 0:
            return response.choices[0].message.content.strip()
        else:
            return None