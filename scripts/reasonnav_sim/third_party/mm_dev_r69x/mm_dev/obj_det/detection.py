#!/usr/bin/env python3

import os

import numpy as np
from PIL import Image
import pyrealsense2 as rs2
from scipy.spatial.transform import Rotation as R

# Open-vocabulary detector backend. REASONNAV_DETECTOR picks between:
#   owlvit (default) - google/owlvit-base-patch32 in PyTorch, the weights
#                      NanoOWL wraps; fast but weak on phrases like "a door".
#   gdino            - IDEA-Research/grounding-dino-base, stronger grounding
#                      of natural-language queries, heavier per frame.
#   yolo             - fixed door/directional_sign/room_label YOLO11s trained
#                      on this building. Fastest and most accurate here, but
#                      answers nothing outside those three classes.
# Both expose the same predictor/draw pair, so nothing below changes.
_BACKEND = os.environ.get('REASONNAV_DETECTOR', 'owlvit').lower()

# Usable depth range, in metres. The D455's stereo error grows with the square
# of range, so past roughly 6 m indoors a reading is noise wearing the costume
# of a measurement -- and the only check here used to be `d > 0`, so 14 m
# readings went straight into landmark positions. Corners of one door were
# landing 1.9 m apart in depth at the median (4.4 m at p90), which moved the
# landmark further than the 1.5 m merge radius and split one door into two.
MIN_DEPTH_M = float(os.environ.get('REASONNAV_MIN_DEPTH', '0.3'))
MAX_DEPTH_M = float(os.environ.get('REASONNAV_MAX_DEPTH', '6.0'))

if _BACKEND in ('yolo', 'yolo11', 'yolov11'):
    # Closed vocabulary: door / directional_sign / room_label only, trained on
    # this building. See mm_dev/obj_det/yolo_torch.py for the query mapping.
    from mm_dev.obj_det.yolo_torch import (YoloPredictor as OwlPredictor,
                                           draw_owl_output, DEFAULT_WEIGHTS)
    DEFAULT_MODEL = DEFAULT_WEIGHTS
elif _BACKEND in ('gdino', 'grounding_dino', 'groundingdino'):
    from mm_dev.obj_det.gdino_torch import (GroundingDinoPredictor as OwlPredictor,
                                            draw_owl_output)
    DEFAULT_MODEL = 'IDEA-Research/grounding-dino-base'
else:
    try:
        from nanoowl.owl_predictor import OwlPredictor
        from nanoowl.owl_drawing import draw_owl_output
    except ImportError:
        # No NanoOWL/TensorRT here: run the same OWL-ViT weights in PyTorch.
        from mm_dev.obj_det.owl_torch import OwlPredictor, draw_owl_output
    DEFAULT_MODEL = 'google/owlvit-base-patch32'
# from transformers import AutoProcessor, Owlv2ForObjectDetection
# import torch


class ObjectDetector:
    def __init__(self, model_name='google/owlvit-base-patch32', image_encoder_engine=None):
        """Initialize the open-vocabulary detector.

        Args:
            model_name (str): Checkpoint to load. The OWL-ViT default is
                treated as "unset" so REASONNAV_DETECTOR=gdino picks up the
                Grounding DINO checkpoint without the caller (or its ROS
                parameter) having to know which backend is active.
            image_encoder_engine (str): TensorRT engine path; NanoOWL only.
        """
        if model_name == 'google/owlvit-base-patch32':
            model_name = DEFAULT_MODEL
        print(f'[obj_det] backend={_BACKEND} model={model_name}')
        self.predictor = OwlPredictor(
            model_name,
            image_encoder_engine=image_encoder_engine
        )
        self.intrinsics = None
        # Optional: with these set, detect_objects reads the RAW depth stream
        # and does the colour->depth lookup itself instead of relying on the
        # driver's aligned_depth_to_color topic (which caps at ~5-7 Hz on CPU
        # while the raw depth stream runs at ~30 Hz).
        self.depth_intrinsics = None
        self.depth_to_color = None
        self.color_to_depth = None

    def set_depth_intrinsics(self, width, height, ppx, ppy, fx, fy, distortion_model, coeffs):
        """Intrinsics of the RAW depth stream (/camera/depth/camera_info)."""
        self.depth_intrinsics = self._make_intrinsics(
            width, height, ppx, ppy, fx, fy, distortion_model, coeffs)

    def set_depth_to_color_extrinsics(self, rotation, translation):
        """Extrinsics from the depth frame to the colour frame.

        Args:
            rotation: 9 floats, column-major 3x3 (realsense2_camera_msgs/Extrinsics)
            translation: 3 floats, metres
        """
        r = [float(v) for v in rotation]
        t = [float(v) for v in translation]
        d2c = rs2.extrinsics()
        d2c.rotation = r
        d2c.translation = t
        # Inverse: R^T, -R^T t. r is column-major, so r[3*c + row].
        rt = [r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]]
        # R^T in column-major is R read row-major, i.e. swap off-diagonals.
        r_inv = [r[0], r[3], r[6], r[1], r[4], r[7], r[2], r[5], r[8]]
        # -R^T t, with R^T stored column-major in r_inv.
        t_inv = [
            -(r_inv[0] * t[0] + r_inv[3] * t[1] + r_inv[6] * t[2]),
            -(r_inv[1] * t[0] + r_inv[4] * t[1] + r_inv[7] * t[2]),
            -(r_inv[2] * t[0] + r_inv[5] * t[1] + r_inv[8] * t[2]),
        ]
        c2d = rs2.extrinsics()
        c2d.rotation = r_inv
        c2d.translation = t_inv
        self.depth_to_color = d2c
        self.color_to_depth = c2d
        del rt

    def has_raw_depth_calibration(self):
        """True when the raw-depth path is fully configured."""
        return (self.depth_intrinsics is not None and
                self.depth_to_color is not None and
                self.intrinsics is not None)

    def color_pixel_to_point(self, u, v, depth_image, depth_units, iters=4):
        """3D point (metres, colour frame) for a colour pixel, using RAW depth.

        Walks the epipolar correspondence the way librealsense's
        rs2_project_color_pixel_to_depth_pixel does: guess a range, project the
        colour ray into the depth image, read the depth there, and re-seed the
        guess. Converges in a few passes for the D455's short baseline.

        Returns None when the pixel has no valid depth.
        """
        guess = 1.5  # metres; any plausible start converges
        point_color = None
        h, w = depth_image.shape[:2]
        for _ in range(iters):
            p_color = rs2.rs2_deproject_pixel_to_point(
                self.intrinsics, [float(u), float(v)], float(guess))
            p_depth = rs2.rs2_transform_point_to_point(self.color_to_depth, p_color)
            ud, vd = rs2.rs2_project_point_to_pixel(self.depth_intrinsics, p_depth)
            ui, vi = int(round(ud)), int(round(vd))
            if not (0 <= ui < w and 0 <= vi < h):
                return None
            z = float(depth_image[vi, ui]) / depth_units
            if not np.isfinite(z) or z <= 0:
                return None
            p_depth2 = rs2.rs2_deproject_pixel_to_point(
                self.depth_intrinsics, [ud, vd], z)
            point_color = rs2.rs2_transform_point_to_point(self.depth_to_color, p_depth2)
            guess = point_color[2]
        return point_color

    def _point_from_color_pixel(self, u, v, depth_image, depth_units):
        """3D point (metres, colour optical frame) for a colour pixel.

        Uses the raw-depth path when the depth calibration is available,
        otherwise falls back to indexing the depth image directly, which is
        only correct if the caller supplied an aligned depth image.
        """
        if self.has_raw_depth_calibration():
            return self._gate(self.color_pixel_to_point(u, v, depth_image,
                                                        depth_units))

        h, w = depth_image.shape[:2]
        ui, vi = int(u), int(v)
        if not (0 <= ui < w and 0 <= vi < h):
            return None
        d = depth_image[vi, ui]
        if not np.isfinite(d) or d <= 0:
            return None
        p = rs2.rs2_deproject_pixel_to_point(self.intrinsics, [ui, vi], float(d))
        return self._gate([c / depth_units for c in p])

    @staticmethod
    def _gate(point):
        """Drop a point whose range is outside what the camera can measure.

        Applied here so every caller -- centre pixel, bbox corners, the median
        grid -- inherits it, rather than each having to remember.
        """
        if point is None:
            return None
        z = float(point[2])                      # forward, colour optical frame
        if not np.isfinite(z) or not (MIN_DEPTH_M <= z <= MAX_DEPTH_M):
            return None
        return point

    @staticmethod
    def _make_intrinsics(width, height, ppx, ppy, fx, fy, distortion_model, coeffs):
        i = rs2.intrinsics()
        i.width = width
        i.height = height
        i.ppx = ppx
        i.ppy = ppy
        i.fx = fx
        i.fy = fy
        if distortion_model == 'plumb_bob':
            i.model = rs2.distortion.brown_conrady
        elif distortion_model == 'equidistant':
            i.model = rs2.distortion.kannala_brandt4
        i.coeffs = coeffs
        return i

    def set_camera_intrinsics(self, width, height, ppx, ppy, fx, fy, distortion_model, coeffs):
        """Set camera intrinsics for 3D projection.
        
        Args:
            width (int): Image width
            height (int): Image height
            ppx (float): Principal point X
            ppy (float): Principal point Y
            fx (float): Focal length X
            fy (float): Focal length Y
            distortion_model (str): Distortion model name
            coeffs (list): Distortion coefficients
        """
        self.intrinsics = rs2.intrinsics()
        self.intrinsics.width = width
        self.intrinsics.height = height
        self.intrinsics.ppx = ppx
        self.intrinsics.ppy = ppy
        self.intrinsics.fx = fx
        self.intrinsics.fy = fy
        
        if distortion_model == 'plumb_bob':
            self.intrinsics.model = rs2.distortion.brown_conrady
        elif distortion_model == 'equidistant':
            self.intrinsics.model = rs2.distortion.kannala_brandt4
            
        self.intrinsics.coeffs = coeffs

    def process_query(self, query_text):
        """Process text query into a list of search terms.
        
        Args:
            query_text (str): Raw query text
            
        Returns:
            list: List of search terms
        """
        query_text = query_text.strip("][()")
        return query_text.split(',')

    def detect_objects(self, rgb_image, depth_image, query_text, thresholds, depth_units=1000):
        """Detect objects in the image based on the query.
        
        Args:
            rgb_image: RGB image as numpy array
            depth_image: Depth image as numpy array
            query_text (str): Text query for object detection
            thresholds (float list): Detection confidence thresholds
            depth_units (float): Depth units in meters (e.g., 1000 for mm)
        Returns:
            tuple: (detections, visualization_image)
                detections: list of dicts containing detection info
                visualization_image: RGB image with detections drawn
        """
        if not self.intrinsics:
            raise RuntimeError("Camera intrinsics not set")

        # Convert numpy array to PIL Image
        pil_image = Image.fromarray(rgb_image)
        
        # Process text query
        text_queries = self.process_query(query_text)
        
        # Encode text queries
        text_encodings = self.predictor.encode_text(text_queries)
        
        # Run detection
        output = self.predictor.predict(
            image=pil_image,
            text=text_queries,
            text_encodings=text_encodings,
            threshold=thresholds,
            pad_square=False
        )

        # inputs = self.predictor(text=text_queries, images=pil_image, return_tensors="pt", threshold=thresholds)
        # with torch.no_grad():
        #     output = self.model(**inputs)
        

        detections = []
        for i in range(len(output.labels)):
            box = []
            w, h = pil_image.size
            for x in output.boxes[i]:
                val = float(x)
                # Clip to the image. float() again because the bounds are ints:
                # a box that runs off the edge comes back as an int, and a box
                # clipped away entirely makes size_x an int 0, which trips
                # `Assertion PyFloat_Check(field)` inside BoundingBox2D and
                # aborts the process. Grounding DINO emits such boxes; OWL-ViT
                # rarely did, so this stayed hidden.
                val = float(max(0.0, min(val, (w - 1) if len(box) % 2 == 0 else (h - 1))))
                box.append(val)
            label_index = int(output.labels[i])
            
            # Calculate center point
            center_x = (box[0] + box[2]) / 2.0
            center_y = (box[1] + box[3]) / 2.0
            
            # A real RealSense reports 0 where it has no depth (dark/specular/
            # too close), which would project to the camera origin and poison
            # everything downstream.
            point_c = self._point_from_color_pixel(
                center_x, center_y, depth_image, depth_units)
            if point_c is None:
                continue
            # RealSense optical (x right, y down, z forward) -> ROS (x forward)
            point_3d = [point_c[2], -point_c[0], -point_c[1]]

            bbox_corners = [
                [box[0], box[1]],
                [box[2], box[1]],
                [box[2], box[3]],
                [box[0], box[3]]
            ]
            bbox_corners_3d = []
            valid_corners_3d = []
            for corner in bbox_corners:
                c3 = self._point_from_color_pixel(
                    corner[0], corner[1], depth_image, depth_units)
                if c3 is None:
                    # No usable depth here. The published corner keeps the old
                    # zero placeholder so the message layout is unchanged, but
                    # it must never reach the averaging below: the camera origin
                    # is not a measurement, and folding it in dragged the door
                    # metres towards the rig. 57% of boxes had at least one such
                    # corner, which is what split single doors into two icons.
                    bbox_corners_3d.append(np.array([0.0, 0.0, 0.0]))
                    continue
                p = np.array([c3[2], -c3[0], -c3[1]])
                bbox_corners_3d.append(p)
                valid_corners_3d.append(p)

            # get normal vector of 3d bounding box
            u = np.array(bbox_corners_3d[1]) - np.array(bbox_corners_3d[0])
            v = np.array(bbox_corners_3d[3]) - np.array(bbox_corners_3d[0])
            normal = np.cross(u, v)
            norm_len = np.linalg.norm(normal)
            # Corners with missing depth make u/v zero or parallel, so the cross
            # product degenerates and normal/norm_len becomes NaN. Fall back to
            # facing the camera rather than emitting a NaN pose.
            if np.isfinite(norm_len) and norm_len > 1e-6:
                normal = normal / norm_len
                yaw = np.arctan2(normal[1], normal[0])
            else:
                yaw = np.arctan2(point_3d[1], point_3d[0])
            if not np.isfinite(yaw):
                continue
            # The cross product's sign depends on corner order, so make the
            # normal point toward the camera: a sign or door face is only ever
            # seen from the side it faces. The disabled version of this used
            # +point_3d (camera -> object), i.e. the wrong way round, which is
            # presumably why it was commented out. Object -> camera is -point_3d.
            if np.isfinite(norm_len) and norm_len > 1e-6:
                to_cam = -np.array(point_3d, dtype=float)
                if np.dot(normal, to_cam) < 0:
                    normal = -normal
                    yaw = np.arctan2(normal[1], normal[0])
            r = R.from_euler('z', yaw, degrees=False)
            quat = r.as_quat()

            # use doorframe (bbox corners) to get center pt of door in case the
            # door is open and the centre ray shoots through the opening.
            if 'door' in text_queries[label_index] or 'sign' in text_queries[label_index]:
                if len(valid_corners_3d) >= 2:
                    point_3d = list(np.mean(np.array(valid_corners_3d), axis=0))
                # else keep the centre point, which was already validated above.
            # if 'sign' in text_queries[label_index]:
                # # orientation use center point
                # x_pt = center_x - 50
                # y_pt = center_y - 50
                # x_depth = depth_image[int(center_y), int(x_pt)]
                # y_depth = depth_image[int(y_pt), int(center_x)]
                # # Project to 3D point
                # x_3d = rs2.rs2_deproject_pixel_to_point(
                #     self.intrinsics,
                #     [int(x_pt), int(center_y)],
                #     x_depth
                # )
                # y_3d = rs2.rs2_deproject_pixel_to_point(
                #     self.intrinsics,
                #     [int(center_x), int(y_pt)],
                #     y_depth
                # )
                # # Convert to meters and ROS coordinate system
                # x_3d = [p / depth_units for p in x_3d]  # mm to meters
                # x_3d = [x_3d[2], -x_3d[0], -x_3d[1]]  # RealSense to ROS coordinates
                # y_3d = [p / depth_units for p in y_3d]  # mm to meters
                # y_3d = [y_3d[2], -y_3d[0], -y_3d[1]]  # RealSense to ROS coordinates
                # # get normal vector of 3d bounding box
                # u = np.array(x_3d) - np.array(point_3d)
                # v = np.array(y_3d) - np.array(point_3d)
                # normal = np.cross(u, v)
                # normal = normal / np.linalg.norm(normal)
                # yaw = np.arctan2(normal[1], normal[0])
                # r = R.from_euler('z', yaw, degrees=False)
                # quat = r.as_quat()
            # if 'label' in text_queries[label_index]:
            #     # orientation use center point
            #     x_pt = center_x - 20
            #     y_pt = center_y - 20
            #     x_depth = depth_image[int(center_y), int(x_pt)]
            #     y_depth = depth_image[int(y_pt), int(center_x)]
            #     # Project to 3D point
            #     x_3d = rs2.rs2_deproject_pixel_to_point(
            #         self.intrinsics,
            #         [int(x_pt), int(center_y)],
            #         x_depth
            #     )
            #     y_3d = rs2.rs2_deproject_pixel_to_point(
            #         self.intrinsics,
            #         [int(center_x), int(y_pt)],
            #         y_depth
            #     )
            #     # Convert to meters and ROS coordinate system
            #     x_3d = [p / depth_units for p in x_3d]  # mm to meters
            #     x_3d = [x_3d[2], -x_3d[0], -x_3d[1]]  # RealSense to ROS coordinates
            #     y_3d = [p / depth_units for p in y_3d]  # mm to meters
            #     y_3d = [y_3d[2], -y_3d[0], -y_3d[1]]  # RealSense to ROS coordinates
            #     # get normal vector of 3d bounding box
            #     u = np.array(x_3d) - np.array(point_3d)
            #     v = np.array(y_3d) - np.array(point_3d)
            #     normal = np.cross(u, v)
            #     normal = normal / np.linalg.norm(normal)
            #     yaw = np.arctan2(normal[1], normal[0])
            #     r = R.from_euler('z', yaw, degrees=False)
            #     quat = r.as_quat()
            if 'person' in text_queries[label_index]:
                x_pt = center_x - 5
                y_pt = center_y - 5
                x_depth = depth_image[int(center_y), int(x_pt)]
                y_depth = depth_image[int(y_pt), int(center_x)]
                # Project to 3D point
                x_3d = rs2.rs2_deproject_pixel_to_point(
                    self.intrinsics,
                    [int(x_pt), int(center_y)],
                    x_depth
                )
                y_3d = rs2.rs2_deproject_pixel_to_point(
                    self.intrinsics,
                    [int(center_x), int(y_pt)],
                    y_depth
                )
                # Convert to meters and ROS coordinate system
                x_3d = [p / depth_units for p in x_3d]  # mm to meters
                x_3d = [x_3d[2], -x_3d[0], -x_3d[1]]  # RealSense to ROS coordinates
                y_3d = [p / depth_units for p in y_3d]  # mm to meters
                y_3d = [y_3d[2], -y_3d[0], -y_3d[1]]  # RealSense to ROS coordinates
                # get normal vector of 3d bounding box
                u = np.array(x_3d) - np.array(point_3d)
                v = np.array(y_3d) - np.array(point_3d)
                normal = np.cross(u, v)
                normal = normal / np.linalg.norm(normal)
                yaw = np.arctan2(normal[1], normal[0])
                r = R.from_euler('z', yaw, degrees=False)
                quat = r.as_quat()

            detection = {
                'bbox': box,
                'label_index': label_index,
                'label': text_queries[label_index].strip(),
                'center_2d': (center_x, center_y),
                'point_3d': point_3d,
                'bbox_corners_3d': bbox_corners_3d,
                'orientation': quat,
                'score': output.scores[i],
                'size_x': abs(box[2] - box[0]),
                'size_y': abs(box[3] - box[1])
            }
            detections.append(detection)

        # Create visualization
        vis_image = draw_owl_output(pil_image, output, text=text_queries, draw_text=True)
        vis_image = np.array(vis_image)
        
        return detections, vis_image

    def has_intrinsics(self):
        """Check if camera intrinsics are set.
        
        Returns:
            bool: True if intrinsics are set, False otherwise
        """
        return self.intrinsics is not None