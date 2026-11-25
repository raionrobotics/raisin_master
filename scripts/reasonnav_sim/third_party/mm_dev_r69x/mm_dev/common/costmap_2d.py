#!/usr/bin/env python3

from typing import Optional, Tuple
from builtin_interfaces.msg import Time
import numpy as np
import cv2  # For debug visualization

# nav2 cost values, mirrored from nav2_costmap_2d/cost_values.hpp.
FREE_SPACE = 0
INSCRIBED_INFLATED_OBSTACLE = 253
LETHAL_OBSTACLE = 254
NO_INFORMATION = 255


def _occupancy_to_cost(data: np.ndarray) -> np.ndarray:
    """Map OccupancyGrid values (-1, 0..100) onto the nav2 cost scale (0..255).

    This is the inverse of what Costmap2DPublisher does on the way out, and
    uses the same anchor points: unknown -> 255, free -> 0, 99 -> inscribed,
    100 -> lethal, and everything between scaled linearly.
    """
    out = np.empty(data.shape, dtype=np.uint8)
    unknown = data < 0
    free = data == 0
    inscribed = data == 99
    lethal = data >= 100
    mid = ~(unknown | free | inscribed | lethal)

    out[unknown] = NO_INFORMATION
    out[free] = FREE_SPACE
    out[inscribed] = INSCRIBED_INFLATED_OBSTACLE
    out[lethal] = LETHAL_OBSTACLE
    # 1..98 -> 1..252
    out[mid] = (1 + (data[mid].astype(np.int32) - 1) * 251 // 97).astype(np.uint8)
    return out


class PyCostmap2D:
    """
    PyCostmap2D.

    Python3 API for nav2_msgs.msg.Costmap messages
    With consistent coordinate transforms and correct orientation
    """

    def __init__(self, costmap) -> None:
        """
        Initialize costmap2D from a nav2_msgs.msg.Costmap or nav_msgs.OccupancyGrid.

        Args
        ----
            costmap: nav2_msgs.msg.Costmap or nav_msgs.OccupancyGrid object
        """
        # Check if we have a nav2_msgs.msg.Costmap object (has 'metadata' attribute)
        if hasattr(costmap, 'metadata') and hasattr(costmap, 'data'):
            # Extract metadata
            self.size_x = costmap.metadata.size_x
            self.size_y = costmap.metadata.size_y
            self.resolution = costmap.metadata.resolution
            self.origin_x = costmap.metadata.origin.position.x
            self.origin_y = costmap.metadata.origin.position.y
            self.global_frame_id = costmap.header.frame_id
            self.costmap_timestamp = costmap.header.stamp
            
            # Extract costmap as 1D array for compatibility with existing code
            self.costmap = np.array(costmap.data, dtype=np.uint8)
            
            # For internal use in get_costmap_as_image - ensure it's not empty
            self._costmap_2d = self.costmap.reshape(self.size_y, self.size_x)
        
        # Check if we have a standard OccupancyGrid (has 'info' attribute)
        elif hasattr(costmap, 'info') and hasattr(costmap, 'data'):
            self.size_x = costmap.info.width
            self.size_y = costmap.info.height
            self.resolution = costmap.info.resolution
            self.origin_x = costmap.info.origin.position.x
            self.origin_y = costmap.info.origin.position.y
            self.global_frame_id = costmap.header.frame_id
            self.costmap_timestamp = costmap.header.stamp

            # An OccupancyGrid speaks a different language from a nav2 Costmap:
            # -1 unknown and 0..100 cost, against 255 unknown and 0..254 cost.
            # Everything downstream (vis_landmarks, the frontier filter) is
            # written against the nav2 scale, so convert here rather than making
            # every reader ask which message it got. Without this a LETHAL cell
            # arrives as 100, falls under vis_landmarks' >100 test and is
            # painted as FREE -- walls rendered as open floor, on the very map
            # the VLM is asked to navigate from.
            self.costmap = _occupancy_to_cost(np.array(costmap.data, dtype=np.int16))

            # For internal use in get_costmap_as_image - ensure it's not empty
            self._costmap_2d = self.costmap.reshape(self.size_y, self.size_x)
        else:
            # Print information about the object to help debugging
            print(f"Unsupported costmap object type: {type(costmap)}")
            print(f"Available attributes: {dir(costmap)}")
            raise TypeError("Unsupported costmap object type")
        
        # Save an image of the original costmap for verification/debugging
        try:
            debug_img = self._costmap_2d.copy()
            # cv2.imwrite("debug_original_costmap.jpg", debug_img)
            
            # Also save the transformed version to verify orientation
            transformed = self.get_costmap_as_image()
            # cv2.imwrite("debug_transformed_costmap.jpg", transformed)
        except Exception as e:
            print(f"Debug image saving failed: {e}")

    def getSizeInCellsX(self) -> int:
        """Get map width in cells."""
        return self.size_x

    def getSizeInCellsY(self) -> int:
        """Get map height in cells."""
        return self.size_y

    def getSizeInMetersX(self) -> float:
        """Get x axis map size in meters."""
        return (self.size_x - 1 + 0.5) * self.resolution

    def getSizeInMetersY(self) -> float:
        """Get y axis map size in meters."""
        return (self.size_y - 1 + 0.5) * self.resolution

    def getOriginX(self) -> float:
        """Get the origin x axis of the map [m]."""
        return self.origin_x

    def getOriginY(self) -> float:
        """Get the origin y axis of the map [m]."""
        return self.origin_y

    def getResolution(self) -> float:
        """Get map resolution [m/cell]."""
        return self.resolution

    def getGlobalFrameID(self) -> str:
        """Get global frame_id."""
        return self.global_frame_id

    def getCostmapTimestamp(self) -> Time:
        """Get costmap timestamp."""
        return self.costmap_timestamp

    def getCostXY(self, mx: int, my: int) -> np.uint8:
        """
        Get the cost of a cell in the costmap using map coordinate XY.

        Args
        ----
            mx (int): map coordinate X to get cost
            my (int): map coordinate Y to get cost

        Returns
        -------
            np.uint8: cost of a cell
        """
        # For coordinates in the transformed image space
        try:
            # Convert mx, my to original costmap coordinates
            orig_mx = self.size_x - my - 1  # Due to transpose + flip
            orig_my = self.size_y - mx - 1  # Due to transpose + flip
            
            # Ensure coordinates are within bounds
            if 0 <= orig_mx < self.size_x and 0 <= orig_my < self.size_y:
                return np.uint8(self.costmap[self.getIndex(orig_mx, orig_my)])
            else:
                print(f"Warning: Coordinates out of bounds - orig_mx={orig_mx}, orig_my={orig_my}")
                return np.uint8(0)
        except Exception as e:
            print(f"Error in getCostXY: {e} for mx={mx}, my={my}")
            return np.uint8(0)

    def getCostIdx(self, index: int) -> np.uint8:
        """
        Get the cost of a cell in the costmap using Index.

        Args
        ----
            index (int): index of cell to get cost

        Returns
        -------
            np.uint8: cost of a cell
        """
        if 0 <= index < len(self.costmap):
            return np.uint8(self.costmap[index])
        else:
            print(f"Warning: Index out of bounds - index={index}, costmap length={len(self.costmap)}")
            return np.uint8(0)

    def setCost(self, mx: int, my: int, cost: np.uint8) -> None:
        """
        Set the cost of a cell in the costmap using map coordinate XY.

        Args
        ----
            mx (int): map coordinate X to get cost
            my (int): map coordinate Y to get cost
            cost (np.uint8): The cost to set the cell

        Returns
        -------
            None
        """
        try:
            # For coordinates in the transformed image space
            # Convert mx, my to original costmap coordinates
            orig_mx = self.size_x - my - 1  # Due to transpose + flip
            orig_my = self.size_y - mx - 1  # Due to transpose + flip
            
            # Ensure coordinates are within bounds
            if 0 <= orig_mx < self.size_x and 0 <= orig_my < self.size_y:
                self.costmap[self.getIndex(orig_mx, orig_my)] = cost
                self._costmap_2d[orig_my, orig_mx] = cost
            else:
                print(f"Warning: Coordinates out of bounds in setCost - orig_mx={orig_mx}, orig_my={orig_my}")
        except Exception as e:
            print(f"Error in setCost: {e} for mx={mx}, my={my}")

    def mapToWorld(self, mx: int, my: int) -> Tuple[float, float]:
        """
        Get the world coordinate XY using map coordinate XY.
        Adjusted for the transformed image orientation.

        Args
        ----
            mx (int): map coordinate X to get world coordinate
            my (int): map coordinate Y to get world coordinate

        Returns
        -------
            tuple of float: wx, wy
            wx (float) [m]: world coordinate X
            wy (float) [m]: world coordinate Y
        """
        try:
            # Handle potential NaN or out-of-bounds inputs
            if not (isinstance(mx, (int, float)) and isinstance(my, (int, float))):
                print(f"Warning: Invalid coordinate types in mapToWorld - mx={type(mx)}, my={type(my)}")
                return (0.0, 0.0)
                
            # For coordinates in the transformed image space
            # Convert mx, my to original costmap coordinates
            orig_mx = self.size_x - my - 1  # Due to transpose + flip
            orig_my = self.size_y - mx - 1  # Due to transpose + flip
            
            # Apply standard transformation from original space
            wx = self.origin_x + (orig_mx + 0.5) * self.resolution
            wy = self.origin_y + (orig_my + 0.5) * self.resolution
            return (wx, wy)
        except Exception as e:
            print(f"Error in mapToWorld: {e} for mx={mx}, my={my}")
            return (0.0, 0.0)

    def worldToMapValidated(self, wx: float, wy: float, scale=1) -> Tuple[Optional[int], Optional[int]]:
        """
        Get the map coordinate XY using world coordinate XY.
        Adjusted for the transformed image orientation.

        Args
        ----
            wx (float) [m]: world coordinate X to get map coordinate
            wy (float) [m]: world coordinate Y to get map coordinate

        Returns
        -------
            (None, None): if coordinates are invalid
            tuple of int: mx, my (if coordinates are valid)
            mx (int): map coordinate X
            my (int): map coordinate Y
        """
        try:
            # Basic input validation
            if not (isinstance(wx, (int, float)) and isinstance(wy, (int, float))):
                print(f"Warning: Invalid coordinate types in worldToMapValidated - wx={type(wx)}, wy={type(wy)}")
                return (None, None)
                
            # if wx < self.origin_x or wy < self.origin_y:
            #     return (None, None)
                
            # Convert to original costmap coordinates first
            orig_mx = int((wx - self.origin_x) // self.resolution)
            orig_my = int((wy - self.origin_y) // self.resolution)
            
            # if orig_mx < self.size_x and orig_my < self.size_y:
            # Convert to transformed image coordinates
            mx = orig_my  # Due to transpose + flip
            mx = self.size_y - mx - 1
            my = orig_mx  # Due to transpose + flip
            my = self.size_x - my - 1
            x_clipped = np.clip(mx, 0, self.size_y - 1)*scale
            y_clipped = np.clip(my, 0, self.size_x - 1)*scale
            return (x_clipped, y_clipped)
        
        except Exception as e:
            print(f"Error in worldToMapValidated: {e} for wx={wx}, wy={wy}")
            return (None, None)

    def getIndex(self, mx: int, my: int) -> int:
        """
        Get the index of the cell using map coordinate XY.

        Args
        ----
            mx (int): map coordinate X to get Index
            my (int): map coordinate Y to get Index

        Returns
        -------
            int: The index of the cell
        """
        if 0 <= mx < self.size_x and 0 <= my < self.size_y:
            return my * self.size_x + mx
        else:
            print(f"Warning: Coordinates out of bounds in getIndex - mx={mx}, my={my}")
            # Return -1, or 0, or somewhere safe in the array
            return 0
    
    def get_costmap_as_image(self):
        """
        Convert the costmap to a 2D image array that matches RViz2 orientation.
        Uses transpose followed by double flip (both axes) as confirmed by the user.
        
        Returns
        -------
            np.ndarray: 2D array representing the costmap in the correct orientation
        """
        # Ensure the costmap 2D representation exists and has the right shape
        if self._costmap_2d.size == 0 or self._costmap_2d.shape != (self.size_y, self.size_x):
            print(f"Warning: Reshaping costmap in get_costmap_as_image. Current shape: {self._costmap_2d.shape}")
            self._costmap_2d = self.costmap.reshape(self.size_y, self.size_x)
            
        # Apply transpose followed by flipping both axes
        transformed = np.flip(self._costmap_2d.T, axis=(0, 1))
        
        if transformed.size == 0:
            print("Error: Transformed costmap is empty!")
            return np.zeros((self.size_x, self.size_y), dtype=np.uint8)
            
        return transformed