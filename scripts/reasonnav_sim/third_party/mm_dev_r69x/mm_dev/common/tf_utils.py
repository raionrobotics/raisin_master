import numpy as np
from geometry_msgs.msg import Transform, Pose, TransformStamped
from tf2_ros import Buffer
from rclpy.time import Time
from scipy.spatial.transform import Rotation as R
def transform_matrix_to_transform_msg(transform_matrix):
    msg = Transform()
    msg.translation.x = transform_matrix[0, 3]
    msg.translation.y = transform_matrix[1, 3]
    msg.translation.z = transform_matrix[2, 3]

    # Convert the 3x3 rotation matrix to quaternion
    rotation_matrix = transform_matrix[0:3, 0:3]
    qw = np.sqrt(1 + rotation_matrix[0, 0] + rotation_matrix[1, 1] + rotation_matrix[2, 2]) / 2
    qx = (rotation_matrix[2, 1] - rotation_matrix[1, 2]) / (4 * qw)
    qy = (rotation_matrix[0, 2] - rotation_matrix[2, 0]) / (4 * qw)
    qz = (rotation_matrix[1, 0] - rotation_matrix[0, 1]) / (4 * qw)

    msg.rotation.x = qx
    msg.rotation.y = qy
    msg.rotation.z = qz
    msg.rotation.w = qw

    return msg
def yaw_to_quaternion(yaw:float) -> tuple[float, float, float, float]:
    return 0., 0., np.sin(yaw / 2), np.cos(yaw / 2)
def transform_msg_to_transform_matrix(msg: Transform):
    # Extract translation
    tx = msg.translation.x
    ty = msg.translation.y
    tz = msg.translation.z

    # Extract quaternion orientation
    qx = msg.rotation.x
    qy = msg.rotation.y
    qz = msg.rotation.z
    qw = msg.rotation.w

    # Convert quaternion to a 3x3 rotation matrix
    rotation_matrix = quaternion_to_rotation_matrix(qx, qy, qz, qw)

    # Create the 4x4 transform matrix
    transform_matrix = np.eye(4)
    transform_matrix[0:3, 0:3] = rotation_matrix
    transform_matrix[0:3, 3] = [tx, ty, tz]

    return transform_matrix
    
def quaternion_to_rotation_matrix(qx, qy, qz, qw):
    return np.array([
        [1 - 2 * (qy ** 2 + qz ** 2), 2 * (qx * qy - qz * qw), 2 * (qx * qz + qy * qw)],
        [2 * (qx * qy + qz * qw), 1 - 2 * (qx ** 2 + qz ** 2), 2 * (qy * qz - qx * qw)],
        [2 * (qx * qz - qy * qw), 2 * (qy * qz + qx * qw), 1 - 2 * (qx ** 2 + qy ** 2)]
    ])

def transform_matrix_to_xyyaw(transform_matrix:np.ndarray) -> tuple[float, float, float]:
    x = transform_matrix[0, 3]
    y = transform_matrix[1, 3]
    yaw = np.arctan2(transform_matrix[1, 0], transform_matrix[0, 0])
    return x, y, yaw
def pose_msg_to_xyyaw(msg: Pose) -> tuple[float, float, float]:
    # use scipy
    r = R.from_quat([msg.orientation.x, msg.orientation.y, msg.orientation.z, msg.orientation.w])
    roll, pitch, yaw = r.as_euler('xyz', degrees=False)
    return msg.position.x, msg.position.y, yaw
def xyyaw_to_pose_msg(x:float, y:float, yaw:float)-> Pose:
    pose_msg = Pose()
    pose_msg.position.x = x
    pose_msg.position.y = y
    pose_msg.position.z = 0.
    pose_msg.orientation.x = 0.
    pose_msg.orientation.y = 0.
    pose_msg.orientation.z = np.sin(yaw / 2)
    pose_msg.orientation.w = np.cos(yaw / 2)
    return pose_msg
def transform_msg_to_pose_msg(msg: Transform) -> Pose:
    transform_matrix = transform_msg_to_transform_matrix(msg)
    x, y, yaw = transform_matrix_to_xyyaw(transform_matrix)
    return xyyaw_to_pose_msg(x, y, yaw)
def pose_msg_to_transform_msg(msg: Pose) -> Transform:
    transform_matrix = np.eye(4)
    transform_matrix[0, 3] = msg.position.x
    transform_matrix[1, 3] = msg.position.y
    transform_matrix[2, 3] = msg.position.z

    # Convert the quaternion to a rotation matrix
    rotation_matrix = quaternion_to_rotation_matrix(
        msg.orientation.x,
        msg.orientation.y,
        msg.orientation.z,
        msg.orientation.w
    )

    transform_matrix[0:3, 0:3] = rotation_matrix

    return transform_matrix_to_transform_msg(transform_matrix)
def transform_msg_to_xyyaw(msg: Transform) -> tuple[float, float, float]:
    transform_matrix = transform_msg_to_transform_matrix(msg)
    return transform_matrix_to_xyyaw(transform_matrix)

def get_tf(frame_t:str, frame_s:str, t:Time, tf_buffer:Buffer, return_stamped=False) -> TransformStamped | Transform | None:
    try:
        transform:TransformStamped = tf_buffer.lookup_transform(
            frame_t,
            frame_s,
            t
        )
        return transform.transform if not return_stamped else transform
    
    except Exception as e:
        print(f"Error getting robot pose: {e}")
        return None