#!/usr/bin/env python3
import rclpy
from rclpy.node import Node

import cv2
import numpy as np
from scipy.io.wavfile import write
import gtts
import sounddevice as sd
import soundfile as sf
from dotenv import load_dotenv
from openai import OpenAI
import os

from mm_dev.common.vlm_utils import VLMClient

load_dotenv('/home/user/colcon_ws/src/mm_dev/config/.env')

SIM = True

if SIM:
    from simulation_interface.srv import NpcChat

class HRIAgent(Node):
    def __init__(self, goal=None):
        super().__init__("hri_agent_node")

        self.vlm_client = VLMClient(model="gpt-4.1-2025-04-14")
        self.convo_history = []
        self.goal = goal
        self.learned_info = []

        # for sim service call
        if SIM:
            self.npc_client = self.create_client(NpcChat, 'npc_chat')
            while not self.npc_client.wait_for_service(timeout_sec=1.0):
                self.get_logger().info('NPC service not available, waiting...')
            self.npc_request = NpcChat.Request()
            self.future = None

        # for real stt
        else:
            self.stt_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            self.duration = 5  # seconds
            self.device_index = None
            for i, device in enumerate(sd.query_devices()):
                if "ReSpeaker 4 Mic" in device['name']:
                    self.device_index = i
                    break
            if self.device_index is None:
                raise ValueError("ReSpeaker 4 Mic Array not found")
            device_info = sd.query_devices(self.device_index, 'input')
            self.fs = int(device_info['default_samplerate'])  # use the default sample rate of the device
            self.channels = device_info['max_input_channels']  # number of channels supported by the device
        
        self.get_logger().info("HRIAgent initialized")

    def speak(self, msg):
        if SIM:
            # call service w npc chat client
            formatted_question = f"id_1 {msg}"

            self.npc_request.question = formatted_question

            self.future = self.npc_client.call_async(self.npc_request)
        else:
            # tts
            tts = gtts.gTTS(msg)
            tts.save("speak.mp3")
            data, fs = sf.read("speak.mp3", dtype='float32')
            sd.play(data, fs)
            sd.wait()
            print("done playing sound")

    def listen(self):
        if SIM:
            # subscribe service call to npc chat
            rclpy.spin_until_future_complete(self, self.future)

            response = ""
            try:
                response = self.future.result().answer
            except Exception as e:
                self.get_logger().warn(f"Service call failed: {e}")

            return response
        else:
            # stt via whisper
            recording = sd.rec(int(self.duration * self.fs), samplerate=self.fs, channels=self.channels, device=self.device_index)
            sd.wait()

            write('output.wav', self.fs, recording)

            audio_file = open("output.wav", "rb")

            transcription = self.stt_client.audio.transcriptions.create(
                model="whisper-1",
                file=audio_file
            )

            return transcription.text

    def think(self, prompt, imgs=None):
        if imgs:
            vlm_result = self.vlm_client.images_text_query_vlm(imgs, prompt)
        else:
            vlm_result = self.vlm_client.text_query_vlm(prompt)
        self.get_logger().info(f"ANSWER: {vlm_result}")
        return vlm_result

    # costmap input should be rotated to match robot orientation
    def initiate(self, costmap, robot_facing):
        prompt = f"""
        You are a delivery robot the current goal: {self.goal}. 
        Given the information you have learned: {self.learned_info},
        what do you want to ask the person in front of you?
        Pick the response that makes the most sense from the following 3 choices.
        Return the number and only the number.

        1. "How can I help you?" (This is used to get a goal, only use if the current goal is None)
        2. "Do you know where {self.goal} is?" (This is used to ask for directions)
        3. "Do you know which room # {self.goal} is in?" (This is used to get directory information)
        """
        vlm_result = self.think(prompt)
        try:
            chosen_number = int(vlm_result)

            if chosen_number == 1: # how can i help you
                self.get_instruct()
            elif chosen_number == 2: # do you know where goal is?
                self.get_dir(costmap, robot_facing)
            elif chosen_number == 3:
                self.get_directory_info() # do you know which room # goal is in?
            
            self.goodbye()
        except:
            return

    def goodbye(self):
        to_say = "Sounds good, thanks!"
        self.speak(to_say)

    def get_instruct(self):
        to_say = "Hi, I am a delivery robot! How can I help you?"
        self.speak(to_say)
        response = self.listen()
        self.get_logger().info(response)
        self.convo_history.append(f"You: {to_say}\nPerson: {response}")

        prompt = f"""What location does the person want me to find?
        Return only the output in the format "Goal: place". Do not include quotations.
        If it is a room number, return Goal: #
        
        {self.convo_history}
        """
        vlm_result = self.think(prompt)

        try:
            self.goal = vlm_result.split(':')[1]
            self.learned_info.append(f"Goal is to find {self.goal}")
        except:
            return

    def get_goal(self):
        return self.goal

    def get_dir(self, costmap, robot_facing):
        prefix = ""
        try:
            room_number = any(char.isdigit() for char in self.goal) # in case of 50A
            prefix = "room"
        except:
            prefix = ""

        to_say = f"Hi, I am a delivery robot! Do you know where {prefix} {self.goal} is?"
        self.speak(to_say)
        response = self.listen()
        self.get_logger().info(response)
        self.convo_history.append(f"You: {to_say}\nPerson: {response}")
        # ASSUMPTION: directions are given relative to robot
        stop = False
        ans = -1
        while not stop:
            prompt = f"""You are a robot 🤖 trying to find {self.goal}. You are facing {robot_facing}. Given the map and the directions by Person, write a short note for your future self to refer to later on how to reach your goal.
            Return only the output in the format "Note: note to self". Do not include quotations.
            The image is already aligned with relative directions, so left means left on the image. In your note to self, use the cardinal directions in the map.
            Also ignore the numbers above each landmark as they will be updated.
            
            Conversation:
            {self.convo_history}
            """
            vlm_result = self.think(prompt, [costmap])

            try:
                ans = vlm_result.split(':')[1]
            except:
                break

            self.get_logger().info(f"Note to self: {ans}")

            # stop = self.confirm_dir(self, note, costmap)
            stop = True

        self.learned_info.append(f"{ans}")

    def confirm_dir(self, note, costmap):
        # pop up window
        window_name = "Directions Map"
        cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
        cv2.imshow(window_name, costmap)

        to_say = f"Ok, based on your directions, I think I should {note} on this map. Does that look right to you?"
        self.speak(to_say)
        response = self.listen()
        self.get_logger().info(f"Confirmed: {response}")
        self.convo_history.append(f"You: {to_say}\nPerson: {response}")
        
        cv2.destroyAllWindows()
        if "yes" in response:
            return True
        else:
            return False

    def get_directory_info(self):
        to_say = f"Hi, I am a delivery robot! Do you know which room # {self.goal} is in?"
        self.speak(to_say)
        response = self.listen()
        self.convo_history.append(f"You: {to_say}\nPerson: {response}")

        prompt = f"""What room # did Person tell me {self.goal} is in?
        Return only the output in the format "Room: #". Do not include quotations.
        
        {self.convo_history}
        """
        vlm_result = self.think(prompt)
        
        try:
            room = vlm_result.split(':')[1]
            self.learned_info.append(f"{self.goal} is in Room {room}")
            self.goal = room
        except:
            return

    def get_new_info(self):
        self.convo_history = []
        if len(self.learned_info) > 0:
            return self.learned_info[-1]
        return ""

    
def main(args=None):
    rclpy.init(args=args)

    node = HRIAgent()
    node.initiate(None, None)    

    try:
        rclpy.spin(node)

    except KeyboardInterrupt:
        pass

    node.destroy_node()
    rclpy.try_shutdown()


if __name__ == '__main__':
    main()