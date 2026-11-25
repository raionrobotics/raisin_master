# VLM Navigation Configuration

This directory contains configuration files for the VLM navigation system.

## Configuration Files

### `vlm_nav_config.yaml`

Main configuration file for VLM navigation. All parameters are organized into logical sections:

#### Navigation Parameters (`navigation:`)
- `update_threshold`: Distance threshold for landmark updates (meters)
- `robot_length`: Robot length for navigation planning (meters)
- `max_reposition_attempts`: Max attempts to reposition for OCR
- `footprint`: Robot footprint vertices in meters

#### Detection Parameters (`detection:`)
- `default_query`: Default object detection classes
- `default_threshold`: Confidence thresholds for each class
- `room_label_query`: Query for room label detection
- `room_label_threshold`: Threshold for room labels

#### Approach Distances (`approach:`)
- `door`: Distance to approach doors (negative = from front)
- `sign`: Distance to approach signs
- `person`: Distance to approach people
- `frontier`: Not used for frontiers

#### VLM Configuration (`vlm:`)
- `model`: OpenAI model to use (e.g., "gpt-4.1-2025-04-14")
- `use_vlm_for_sign_direction`: Use VLM vs TF for direction conversion

#### Frontier Exploration (`frontier:`)
- `max_footprint_cost`: Max costmap cost for valid frontier
- `spin_angle`: Rotation angle at frontiers (radians)

#### Task Configuration (`task:`)
- `goal`: Target room number

#### Ablation Modes (`ablation:`)
- `mode`: Ablation study mode (0-7)
  - 0 = none
  - 1 = no map
  - 2 = no info
  - 3 = no vlm (random)
  - 4 = no vlm (closest)
  - 5 = no json
  - 6 = switch vlm api
  - 7 = add front-camera image

#### Paths (`paths:`)
- `costmap_save_dir`: Directory to save costmap data

#### Timeouts (`timeouts:`)
- `navigation_timeout`: Navigation timeout (seconds)
- `pan_timeout`: Pan-tilt timeout (seconds)
- `detection_wait`: Wait time for detection (seconds)
- `detection_retry_wait`: Wait between detection retries (seconds)

## Usage

### Default Configuration

The system automatically loads `vlm_nav_config.yaml` from this directory.

### Custom Configuration

To use a custom config file:

```python
from mm_dev.common.config_loader import VLMNavConfig

# Load custom config
config = VLMNavConfig("/path/to/custom_config.yaml")

# Access parameters
robot_length = config.get('navigation.robot_length')
vlm_model = config.vlm['model']
```

### Modifying Parameters

1. Edit `vlm_nav_config.yaml` directly
2. Restart the navigation node for changes to take effect

### Example Customizations

**Change target room:**
```yaml
task:
  goal: 3010
```

**Adjust robot footprint:**
```yaml
navigation:
  footprint:
    - [0.4, 0.3]
    - [0.4, -0.3]
    - [-0.4, -0.3]
    - [-0.4, 0.3]
```

**Use different VLM model:**
```yaml
vlm:
  model: "gpt-4o"
```

**Adjust detection thresholds:**
```yaml
detection:
  default_threshold: [0.25, 0.35, 0.1]  # [person, door, sign]
```

## Important Notes

- All distance values are in **meters**
- All angle values are in **radians**
- Approach distances are **negative** to approach from the front
- Changes require **restarting** the navigation node
- Invalid YAML syntax will cause the system to fail to start