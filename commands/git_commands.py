"""
Git commands for RAISIN.

Manages multiple git repositories in src/ directory.
"""

import os
import re
import subprocess
import click
import concurrent.futures
from pathlib import Path

# Import globals
from commands import globals as g


# ============================================================================
# Helper Functions
# ============================================================================


def get_display_width(text):
    """
    Calculates the display width of a string, accounting for specific wide characters.
    """
    # Emojis used in this script that take up 2 character spaces
    wide_chars = {"✅", "⬇️", "⬆️", "🔱", "⚠️"}
    width = 0
    for char in text:
        if char in wide_chars:
            width += 2
        else:
            width += 1
    return width


def run_command(command, cwd):
    """A helper function to run a shell command in a specific directory."""
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr.strip()}"
    except FileNotFoundError:
        return "Error: Git command not found."


def get_repo_sort_key(repo_dict):
    """
    Creates a sort key for a repo. It sorts by the first remote's owner,
    then by the repo name, all case-insensitive.
    """
    remotes = repo_dict.get("remotes")
    primary_owner = "~~~~~"  # Default sort key to push items with no remotes to the end

    if remotes:  # Make sure the remotes list is not empty
        primary_owner = remotes[0].get(
            "owner", "~~~~~"
        )  # Get owner of the first remote

    repo_name = repo_dict.get("name", "")

    # Return a tuple: this sorts by owner first, then by name.
    # .lower() ensures sorting is case-insensitive
    return (primary_owner.lower(), repo_name.lower())


def _ensure_github_token():
    """Load GitHub tokens from configuration_setting.yaml."""
    # Import here to avoid circular dependency
    from commands.install import load_configuration

    _, tokens, _, _, _ = load_configuration()
    return tokens


def _run_git_command(command, cwd, timeout=30, silent=False):
    """
    Helper to run a Git command, return its stripped output, and handle errors.

    Args:
        command: Git command as a list
        cwd: Working directory for the command
        timeout: Timeout in seconds (default: 30, use 300 for clone operations)
        silent: If True, don't print error messages (caller handles them)

    Note: Token authentication only works for HTTPS URLs.
    """
    try:
        # --- HTTPS Token Authentication ---
        env = os.environ.copy()
        tokens = _ensure_github_token()

        if tokens:
            # Using .get() is safer than assuming a token exists
            token = tokens.get("github.com")  # Prefer a specific key if available
            if not token:
                token = next(iter(tokens.values()), None)  # Fallback to first token

            if token:
                env["GIT_CONFIG_COUNT"] = "1"
                env["GIT_CONFIG_KEY_0"] = "credential.https://github.com.helper"
                env["GIT_CONFIG_VALUE_0"] = (
                    f'!f() {{ echo "username={token}"; echo "password="; }}; f'
                )

        # Using a timeout is safer for network operations like fetch
        result = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
            timeout=timeout,
        )
        return result.stdout.strip()

    except subprocess.CalledProcessError as e:
        if not silent:
            # Print the actual error message from Git
            error_output = e.stderr.strip()
            cwd_name = os.path.basename(cwd) if cwd else "unknown"
            print(f"  ! Git command failed in '{cwd_name}'. Error: {error_output}")
        return None
    except subprocess.TimeoutExpired:
        if not silent:
            cwd_name = os.path.basename(cwd) if cwd else "unknown"
            print(f"  ! Git command timed out in '{cwd_name}' after {timeout} seconds.")
        return None
    except FileNotFoundError:
        if not silent:
            print(f"  ! Git command not found. Is Git installed and in your PATH?")
        return None


def _get_remote_details(cwd):
    """
    Parses `git remote -v` to get a dict of {name: {'owner': owner}}.
    """
    remote_output = _run_git_command(["git", "remote", "-v"], cwd)
    if not remote_output:
        return {}

    remotes = {}
    # Regex to capture owner from ssh (git@github.com:OWNER/...) or https (https://github.com/OWNER/...)
    url_pattern = re.compile(r"(?:[:/])([^/]+)/([^/.]+)(?:\.git)?$")

    for line in remote_output.splitlines():
        if "(fetch)" not in line:
            continue

        try:
            name, url, _ = line.split()
            if name not in remotes:
                owner = "?"
                match = url_pattern.search(url)
                if match:
                    owner = match.group(1)  # Get the first capture group (the owner)
                remotes[name] = {"owner": owner}
        except ValueError:
            continue  # Skip malformed lines

    return remotes


def _get_git_status(cwd, branch, remote_name):
    """Compares local HEAD to a specific remote branch and returns a status string."""
    remote_branch = f"{remote_name}/{branch}"

    # Check if the remote tracking branch exists
    if (
        _run_git_command(
            ["git", "show-ref", "--verify", "--quiet", f"refs/remotes/{remote_branch}"],
            cwd,
        )
        is None
    ):
        return f"No remote '{branch}'"

    # Get ahead/behind counts using git rev-list
    counts_output = _run_git_command(
        ["git", "rev-list", "--left-right", "--count", f"HEAD...{remote_branch}"], cwd
    )
    if counts_output is None:
        return "Compare failed"

    try:
        ahead_str, behind_str = counts_output.split("\t")
        ahead = int(ahead_str)
        behind = int(behind_str)
    except Exception:
        return "Parse failed"

    # Format the status string
    if ahead > 0 and behind > 0:
        return f"Diverged (A {ahead}, B {behind})"
    elif ahead > 0:
        return f"Ahead {ahead}"
    elif behind > 0:
        return f"Behind {behind}"
    else:
        return "Up-to-date"


def _get_local_changes(cwd):
    """Gets a short summary of local uncommitted changes."""
    status_output = _run_git_command(["git", "status", "--porcelain"], cwd)
    if status_output is None:
        return "Git Error"
    if not status_output:
        return "No changes"

    # Provide a summary
    changed_files = 0
    untracked_files = 0
    for line in status_output.splitlines():
        if line.startswith("??"):
            untracked_files += 1
        else:
            changed_files += 1

    parts = []
    if changed_files > 0:
        # Try to get the diffstat format
        diff_stat = _run_git_command(["git", "diff", "--shortstat", "HEAD"], cwd)
        if diff_stat:
            # " 1 file changed, 53 insertions(+), 12 deletions(-)" -> "1 file, 53+, 12-"
            stat_summary = (
                diff_stat.strip()
                .replace(" changed", "")
                .replace(" files", "f")
                .replace(" file", "f")
                .replace(" insertions", "")
                .replace(" insertion", "")
                .replace(" deletions", "")
                .replace(" deletion", "")
                .replace("(", "")
                .replace(")", "")
            )
            parts.append(stat_summary)
        else:
            parts.append(f"{changed_files} modified")  # Fallback

    if untracked_files > 0:
        parts.append(f"{untracked_files} untracked")

    return ", ".join(parts)


def _find_src_git_repos(base_directory=None):
    """
    Locate git repositories directly under the src/ directory.
    """
    base_dir = Path(base_directory or os.getcwd())
    src_path = base_dir / "src"
    if not src_path.is_dir():
        return []
    return [
        str(repo_path)
        for repo_path in src_path.iterdir()
        if repo_path.is_dir() and (repo_path / ".git").is_dir()
    ]

def process_repo(repo_path, pull_mode, origin="origin"):
    """
    Processes a single Git repository.
    - If pull_mode=True: Attempts to pull the specified 'origin' and returns a simple status dict.
    - If pull_mode=False: Fetches all remotes, checks local changes, and compares HEAD to ALL remote branches.
    """
    repo_name = os.path.basename(repo_path)

    # --- PATH 1: PULL MODE ---
    if pull_mode:
        # Get owner details
        remote_details = _get_remote_details(repo_path)
        owner = remote_details.get(origin, {}).get("owner")

        try:
            # Get the current branch name
            current_branch = _run_git_command(
                ["git", "symbolic-ref", "--short", "HEAD"], repo_path
            )
            if not current_branch:
                raise Exception("Detached HEAD: Cannot pull.")

            # Run git pull command
            pull_result = _run_git_command(
                ["git", "pull", origin, current_branch, "--ff-only"], repo_path
            )

            if pull_result is None:
                raise Exception("Git pull command failed with no output.")

            pull_result = pull_result.strip()

            if "Already up to date." in pull_result or pull_result == "":
                message = "Already up to date."
            else:
                # Any other output implies changes were pulled
                message = pull_result.split("\n")[-1].strip()

            return {
                "name": repo_name,
                "owner": owner,
                "status": "Success",
                "message": message,
            }

        except Exception as e:
            error_message = str(e)
            if hasattr(e, "stderr") and e.stderr:
                error_message = e.stderr.decode().strip().split("\n")[-1]
            elif hasattr(e, "stdout") and e.stdout:
                error_message = e.stdout.decode().strip().split("\n")[-1]

            # Clean common git error prefixes
            if error_message.startswith("fatal:"):
                error_message = error_message[len("fatal: ") :]

            return {
                "name": repo_name,
                "owner": owner,
                "status": "Fail",
                "message": error_message,
            }

    # --- PATH 2: STATUS CHECK MODE ---
    # Get current branch
    current_branch = _run_git_command(
        ["git", "symbolic-ref", "--short", "HEAD"], repo_path
    )
    if not current_branch:
        # Handle detached HEAD state
        current_branch = (
            _run_git_command(["git", "rev-parse", "--short", "HEAD"], repo_path)
            or "DETACHED"
        )
        if "DETACHED" in current_branch:
            return {
                "name": repo_name,
                "branch": current_branch,
                "changes": "N/A (Detached HEAD)",
                "remotes": [],
            }

    # Get local changes
    local_changes = _get_local_changes(repo_path)

    # Get all remotes and their owners
    remote_details = _get_remote_details(repo_path)
    if not remote_details:
        return {
            "name": repo_name,
            "branch": current_branch,
            "changes": local_changes,
            "remotes": [
                {"name": "N/A", "owner": "N/A", "status": "No remotes configured"}
            ],
        }

    # Fetch ALL remotes to get up-to-date info
    _run_git_command(["git", "fetch", "--all", "--quiet"], repo_path)

    # Build the final remotes list with status for each one
    remotes_list = []
    for remote_name, details in remote_details.items():
        # Check status of our local branch against this remote's version
        status_str = _get_git_status(repo_path, current_branch, remote_name)

        remotes_list.append(
            {"name": remote_name, "owner": details["owner"], "status": status_str}
        )

    # Sort remotes alphabetically
    remotes_list.sort(key=lambda x: x["name"])

    # Return the complete data structure
    return {
        "name": repo_name,
        "branch": current_branch,
        "changes": local_changes,
        "remotes": remotes_list,
    }


# ============================================================================
# Main Command Functions
# ============================================================================


def git_clone_command(repos):
    """
    Clone repositories into src/ directory.

    Args:
        repos (list): List of repository specifications. If empty, clones all from repositories.yaml.
            Each repo can be:
            - A name from repositories.yaml (e.g., 'raisin')
            - A shorthand 'owner/repo' (e.g., 'raionrobotics/raisin')
            - A full URL (e.g., 'git@github.com:owner/repo.git')
    """
    from commands.utils import load_configuration

    script_directory = g.script_directory or os.getcwd()
    src_directory = Path(script_directory) / "src"

    # Ensure src/ directory exists
    src_directory.mkdir(parents=True, exist_ok=True)

    # Load repositories from configuration
    all_repositories, _, _, _, _ = load_configuration()

    # If no repos specified, clone all from repositories.yaml
    if not repos:
        if not all_repositories:
            print("❌ No repositories found in repositories.yaml")
            return
        print(f"📦 Cloning all {len(all_repositories)} repositories from repositories.yaml...")
        repos = list(all_repositories.keys())

    success_count = 0
    fail_count = 0

    for repo in repos:
        clone_url = None
        target_name = None

        # Case 1: Check if it's a name in repositories.yaml
        if repo in all_repositories:
            repo_info = all_repositories[repo]
            release_url = repo_info.get("url", "")
            # Extract owner from release URL and construct source repo URL (using HTTPS for token auth)
            # e.g., git@github.com:raionrobotics/raisin_release.git -> https://github.com/raionrobotics/raisin.git
            match = re.search(r"git@github\.com:([^/]+)/", release_url)
            if match:
                owner = match.group(1)
                clone_url = f"https://github.com/{owner}/{repo}.git"
            else:
                # Fallback: assume raionrobotics as default owner
                clone_url = f"https://github.com/raionrobotics/{repo}.git"
            target_name = repo

        # Case 2: Check if it's already a full URL (SSH or HTTPS)
        elif repo.startswith("git@") or repo.startswith("https://") or repo.startswith("http://"):
            clone_url = repo
            # Convert SSH URL to HTTPS for token authentication
            if repo.startswith("git@github.com:"):
                # git@github.com:owner/repo.git -> https://github.com/owner/repo.git
                clone_url = repo.replace("git@github.com:", "https://github.com/")
            # Extract repo name from URL
            match = re.search(r"[:/]([^/]+)/([^/]+?)(?:\.git)?$", repo)
            if match:
                target_name = match.group(2)
            else:
                print(f"❌ {repo}: Could not parse repository name from URL")
                fail_count += 1
                continue

        # Case 3: Check if it's a shorthand 'owner/repo'
        elif "/" in repo:
            owner, repo_name = repo.split("/", 1)
            clone_url = f"https://github.com/{owner}/{repo_name}.git"
            target_name = repo_name

        else:
            print(f"❌ {repo}: Not found in repositories.yaml and is not a valid URL or shorthand")
            fail_count += 1
            continue

        # Check if target directory already exists
        target_path = src_directory / target_name
        if target_path.exists():
            print(f"⚠️  {target_name}: Directory already exists, skipping")
            continue

        print(f"⬇️  Cloning {target_name} from {clone_url}...")

        # Use _run_git_command with longer timeout for clone operations
        result = _run_git_command(
            ["git", "clone", clone_url, str(target_path)],
            cwd=script_directory,
            timeout=300,  # 5 minute timeout for large repos
            silent=False,  # Show git errors for debugging
        )

        if result is not None:
            print(f"✅ {target_name}: Cloned successfully")
            success_count += 1
        else:
            fail_count += 1

    # Print summary
    print(f"\n--- Clone Summary ---")
    print(f"✅ Success: {success_count}")
    if fail_count > 0:
        print(f"❌ Failed: {fail_count}")


def git_status_command():
    """
    Shows git status for all repositories in current directory and './src'.
    """
    manage_git_repos(pull_mode=False)


def git_pull_command(origin="origin"):
    """
    Pulls updates for all repositories from the specified origin.

    Args:
        origin (str): Remote name to pull from (default: "origin")
    """
    manage_git_repos(pull_mode=True, origin=origin)


def manage_git_repos(pull_mode, origin="origin"):
    """
    Manages Git repositories in the current directory and './src'.
    - Default: Checks status.
    - With pull_mode=True: Pulls and provides a clean summary.
    """
    # Find all git repositories
    repo_paths = []
    current_dir = os.getcwd()
    if os.path.isdir(os.path.join(current_dir, ".git")):
        repo_paths.append(current_dir)

    repo_paths.extend(_find_src_git_repos(current_dir))

    if not repo_paths:
        print("No Git repositories found.")
        return

    # Process all repos in parallel
    all_results = list(
        concurrent.futures.ThreadPoolExecutor().map(
            lambda path: process_repo(path, pull_mode=pull_mode, origin=origin),
            repo_paths,
        )
    )
    all_results.sort(key=get_repo_sort_key)

    if pull_mode:
        # Display pull summary
        print("\n--- Pull Summary ---")
        summary_names = [
            f"{res['name']} ({res['owner']})" if res.get("owner") else res["name"]
            for res in all_results
        ]
        max_name = max(len(name) for name in summary_names)
        for i, res in enumerate(all_results):
            icon = "✅" if res.get("status") == "Success" else "❌"

            if res:
                message = res.get("message", "Processing failed: No message returned.")
            else:
                message = "CRITICAL ERROR: Worker process returned None."
                icon = "❌"

            print(f"{icon} {summary_names[i]:<{max_name}}  ->  {message}")
    else:
        # Display status table
        # Discover all unique remote names to use as column headers
        all_remote_names = set()
        for repo in all_results:
            for remote in repo.get("remotes", []):
                if "name" in remote:
                    all_remote_names.add(remote["name"])

        # Create a consistent, sorted list of remote names
        sorted_remote_names = sorted(list(all_remote_names))

        # Build the display_rows data structure with dynamic remote keys
        display_rows = []
        for repo in all_results:
            # Basic info for the static columns
            row_data = {
                "name": repo.get("name", "?"),
                "branch": repo.get("branch", "?"),
            }
            local_changes = repo.get("changes", "No changes")

            # Create a lookup map for the remotes this specific repo has
            repo_remotes_map = {r.get("name"): r for r in repo.get("remotes", [])}

            # Populate the data for each dynamic remote column
            for remote_name in sorted_remote_names:
                if remote_name in repo_remotes_map:
                    # This repo HAS this remote
                    remote = repo_remotes_map[remote_name]
                    owner = remote.get("owner", "?")
                    r_status = remote.get("status", "Unknown")
                    cell_string = f"{owner} - {r_status}, {local_changes}"
                    row_data[remote_name] = cell_string
                else:
                    # This repo does NOT have this remote
                    row_data[remote_name] = "-"

            display_rows.append(row_data)

        # Define the headers dictionary
        headers = {
            "REPOSITORY": "name",
            "BRANCH": "branch",
        }
        # Add the remote names as headers
        for r_name in sorted_remote_names:
            headers[r_name.upper()] = r_name

        # Calculate max widths
        max_widths = {}
        for header_text, key in headers.items():
            header_width = get_display_width(header_text)
            max_data_width = 0
            if display_rows:
                max_data_width = max(
                    get_display_width(row.get(key, "")) for row in display_rows
                )
            max_widths[key] = max(header_width, max_data_width)

        # Build and print the header row
        header_parts = []
        for header_text, key in headers.items():
            width = max_widths[key]
            header_parts.append(
                header_text + " " * (width - get_display_width(header_text))
            )
        header_str = " | ".join(header_parts)
        print(header_str)
        print("-" * get_display_width(header_str))

        # Build and print each data row
        for row in display_rows:
            row_parts = []
            for header_text, key in headers.items():
                width = max_widths[key]
                value = row.get(key, "")
                padded_value = value + " " * (width - get_display_width(value))
                row_parts.append(padded_value)
            print(" | ".join(row_parts))


def git_setup_remotes_command(remote_specs):
    """
    Sets up git remotes for all repositories in src/.

    Args:
        remote_specs (list): List of "name:user" specifications
                            Example: ["origin:raionrobotics", "fork:myuser"]
    """
    try:
        script_directory = g.script_directory
        src_directory = os.path.join(script_directory, "src")

        if not os.path.isdir(src_directory):
            print(f"Error: 'src' directory not found at '{src_directory}'")
            return

        print(f"Scanning for git repositories in '{src_directory}'...")

        for repo_name in os.listdir(src_directory):
            repo_path = os.path.join(src_directory, repo_name)

            if os.path.isdir(repo_path) and os.path.isdir(
                os.path.join(repo_path, ".git")
            ):
                print(f"\n--- Configuring repository: {repo_name} ---")

                # DISCOVER: Get the actual repo name from the existing 'origin' remote URL
                github_repo_name = None
                origin_url = run_command(
                    ["git", "remote", "get-url", "origin"], cwd=repo_path
                )

                if origin_url and origin_url.strip():
                    # Regex to find 'user/repo' from SSH or HTTPS GitHub URLs
                    match = re.search(
                        r"github\.com[:/]([\w-]+/[\w.-]+?)(\.git)?$", origin_url.strip()
                    )
                    if match:
                        # Extract the 'repo' part from the full 'user/repo' path
                        full_repo_path = match.group(1)
                        github_repo_name = full_repo_path.split("/")[-1]
                        print(f"  - Discovered GitHub repo name: '{github_repo_name}'")

                if not github_repo_name:
                    print(
                        f"  ! Warning: Could not discover repo name from 'origin'. Falling back to directory name."
                    )
                    github_repo_name = repo_name  # Fallback

                # Robustly get and delete existing remotes
                print("Checking for existing remotes...")
                remotes_result = run_command(["git", "remote"], cwd=repo_path)

                if remotes_result and remotes_result.strip():
                    existing_remotes = remotes_result.strip().split("\n")
                    for remote in existing_remotes:
                        print(f"  - Removing existing remote: '{remote}'")
                        run_command(["git", "remote", "remove", remote], cwd=repo_path)
                else:
                    print("  - No existing remotes found.")

                # Add new remotes using the discovered repo name
                for spec in remote_specs:
                    try:
                        remote_name, user_or_org = spec.split(":", 1)
                        url = f"git@github.com:{user_or_org}/{github_repo_name}.git"
                        print(f"  + Adding new remote: '{remote_name}' -> {url}")
                        run_command(
                            ["git", "remote", "add", remote_name, url], cwd=repo_path
                        )
                    except ValueError:
                        print(f"  ! Skipping malformed remote specification: '{spec}'.")

        print("\n✅ Git remote setup complete.")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# ============================================================================
# Click CLI Commands
# ============================================================================


@click.group()
def git_group():
    """
    Git repository operations across multiple repos.

    \b
    Examples:
        raisin git status                    # Show status of all repos
        raisin git pull                      # Pull all repos from origin
        raisin git pull --remote upstream    # Pull from upstream
        raisin git fetch --remote origin     # Fetch from origin
        raisin git checkout --branch feature # Checkout existing branch in src repos
        raisin git setup main:user1 dev:user2  # Setup remotes
    """
    pass


@git_group.command("clone")
@click.argument("repos", nargs=-1, required=False)
def git_clone_cli(repos):
    """
    Clone repositories into src/ directory.

    \b
    REPOS can be:
      - Names from repositories.yaml (e.g., 'raisin')
      - Shorthand 'owner/repo' (e.g., 'raionrobotics/raisin')
      - Full URLs (e.g., 'git@github.com:owner/repo.git')

    \b
    If no arguments given, clones all repositories from repositories.yaml.

    \b
    Examples:
        raisin git clone                             # Clone all from repositories.yaml
        raisin git clone raisin                      # Clone single repo
        raisin git clone raisin raisin_plugin        # Clone multiple repos
        raisin git clone raionrobotics/raisin        # Shorthand
        raisin git clone git@github.com:user/repo.git  # Full URL
    """
    git_clone_command(list(repos))


@git_group.command("status")
def git_status_cli():
    """
    Show git status for all repositories.

    \b
    Examples:
        raisin git status
    """
    git_status_command()


@git_group.command("pull")
@click.option(
    "--remote", "-r", default="origin", show_default=True, help="Remote to pull from"
)
def git_pull_cli(remote):
    """
    Pull updates from remote for all repositories.

    \b
    Examples:
        raisin git pull                      # Pull from origin
        raisin git pull --remote upstream    # Pull from upstream
    """
    git_pull_command(origin=remote)


@git_group.command("setup")
@click.argument("remotes", nargs=-1, required=True)
def git_setup_cli(remotes):
    """
    Setup git remotes for all repositories.

    \b
    REMOTES: Remote specifications in format name:username

    \b
    Examples:
        raisin git setup main:user1                  # Setup one remote
        raisin git setup main:user1 dev:user2        # Setup multiple remotes
    """
    remotes = list(remotes)
    git_setup_remotes_command(remotes)


@git_group.command("checkout")
@click.option(
    "--branch",
    "-b",
    required=True,
    help="Branch to checkout or create across repositories in src/",
)
def git_checkout_cli(branch):
    """
    Checkout a branch for all repositories under src (creates it if missing).

    \b
    Examples:
        raisin git checkout --branch feature-123
        raisin git checkout -b hotfix/login-redirect
    """
    git_checkout_command(branch)


@git_group.command("fetch")
@click.option(
    "--remote",
    "-r",
    default="origin",
    show_default=True,
    help="Remote to fetch from for repositories in src/",
)
def git_fetch_cli(remote):
    """
    Fetch updates from a remote for all repositories under src/.

    \b
    Examples:
        raisin git fetch --remote origin
        raisin git fetch -r upstream
        raisin git delete-branch --branch old-feature
        raisin git list-branches
        raisin git push-current --remote origin
    """
    git_fetch_command(remote=remote)


@git_group.command("delete-branch")
@click.option(
    "--branch",
    "-b",
    required=True,
    help="Branch to delete across repositories in src/",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Force delete unmerged branch (uses 'git branch -D')",
)
def git_delete_branch_cli(branch, force):
    """
    Delete a local branch across all repositories under src/.

    \b
    Examples:
        raisin git delete-branch --branch old-feature
        raisin git delete-branch -b wip/api -f
    """
    git_delete_branch_command(branch=branch, force=force)


@git_group.command("list-branches")
def git_list_branches_cli():
    """
    List local branches across all repositories under src/.

    \b
    Examples:
        raisin git list-branches
    """
    git_list_branches_command()


@git_group.command("push-current")
@click.option(
    "--remote",
    "-r",
    default="origin",
    show_default=True,
    help="Remote to push current branch to",
)
def git_push_current_cli(remote):
    """
    Push the current branch to the same branch name on the specified remote
    for all repositories under src/.

    \b
    Examples:
        raisin git push-current --remote origin
        raisin git push-current -r upstream
    """
    git_push_current_command(remote=remote)


def git_checkout_command(branch):
    """
    Checkout a branch across all repositories in src, creating it locally if needed.
    """
    base_directory = g.script_directory or os.getcwd()
    repo_paths = _find_src_git_repos(base_directory)

    if not repo_paths:
        print("No Git repositories found in 'src'.")
        return

    print(f"Checking out branch '{branch}' across repositories in 'src'...")
    for repo_path in repo_paths:
        repo_name = os.path.basename(repo_path)

        # Check if the branch already exists locally
        # Check if the branch already exists locally and check it out
        try:
            subprocess.run(
                ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
                cwd=repo_path,
                check=True,
                capture_output=True,
            )
            # Branch exists, so check it out
            result = _run_git_command(["git", "checkout", branch], repo_path)
            if result is None:
                print(f"❌ {repo_name}: Checkout failed.")
            else:
                default_message = f"Checked out branch '{branch}'."
                message = result.splitlines()[-1] if result else default_message
                print(f"✅ {repo_name}: {message}")
        except subprocess.CalledProcessError:
            # This means the branch does not exist
            print(f"⚠️ {repo_name}: Branch '{branch}' not found locally. Skipping.")
            continue
        except FileNotFoundError:
            print(f"❌ {repo_name}: Git command not found.")
            continue


def git_fetch_command(remote="origin"):
    """
    Fetch updates from the specified remote for all repositories in src/.
    """
    base_directory = g.script_directory or os.getcwd()
    repo_paths = _find_src_git_repos(base_directory)

    if not repo_paths:
        print("No Git repositories found in 'src'.")
        return

    print(f"Fetching from '{remote}' across repositories in 'src'...")
    for repo_path in repo_paths:
        repo_name = os.path.basename(repo_path)
        result = _run_git_command(["git", "fetch", remote], repo_path)
        if result is None:
            print(f"❌ {repo_name}: Fetch failed.")
        else:
            message = result.splitlines()[-1] if result else "Fetch completed."
            print(f"✅ {repo_name}: {message}")


def git_delete_branch_command(branch, force=False):
    """
    Delete a local branch across all repositories in src/.

    Args:
        branch (str): Branch name to delete.
        force (bool): Use -D to force delete even if not fully merged.
    """
    base_directory = g.script_directory or os.getcwd()
    repo_paths = _find_src_git_repos(base_directory)

    if not repo_paths:
        print("No Git repositories found in 'src'.")
        return

    flag = "-D" if force else "-d"
    print(
        f"Deleting branch '{branch}' ({flag}) across repositories in 'src'..."
    )

    for repo_path in repo_paths:
        repo_name = os.path.basename(repo_path)

        # Determine current branch to avoid deleting the active one
        current_branch = _run_git_command(
            ["git", "symbolic-ref", "--short", "HEAD"], repo_path
        )
        if current_branch is None:
            print(f"❌ {repo_name}: Unable to determine current branch. Skipping.")
            continue
        if current_branch == branch:
            print(f"⚠️ {repo_name}: Branch '{branch}' is currently checked out. Skipping.")
            continue

        # Check if branch exists locally
        try:
            subprocess.run(
                ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            branch_exists = True
        except subprocess.CalledProcessError:
            branch_exists = False
        except FileNotFoundError:
            print(f"❌ {repo_name}: Git command not found.")
            continue

        if not branch_exists:
            print(f"⚠️ {repo_name}: Branch '{branch}' not found locally. Skipping.")
            continue

        result = _run_git_command(["git", "branch", flag, branch], repo_path)
        if result is None:
            print(f"❌ {repo_name}: Failed to delete branch '{branch}'.")
        else:
            message = result.splitlines()[-1] if result else f"Deleted '{branch}'."
            print(f"✅ {repo_name}: {message}")


def git_list_branches_command():
    """
    List local branches for all repositories in src/.
    """
    base_directory = g.script_directory or os.getcwd()
    repo_paths = _find_src_git_repos(base_directory)

    if not repo_paths:
        print("No Git repositories found in 'src'.")
        return

    print("Listing local branches for repositories in 'src'...")
    for repo_path in repo_paths:
        repo_name = os.path.basename(repo_path)

        current_branch = _run_git_command(
            ["git", "symbolic-ref", "--short", "HEAD"], repo_path
        )
        result = _run_git_command(
            ["git", "branch", "--format", "%(refname:short)"], repo_path
        )
        if result is None:
            print(f"❌ {repo_name}: Failed to list branches.")
            continue

        branches = [b.strip() for b in result.splitlines() if b.strip()]
        if branches:
            formatted = []
            for b in branches:
                if current_branch and b == current_branch:
                    formatted.append(click.style(b, fg="green"))
                else:
                    formatted.append(b)
            print(f"✅ {repo_name}: {', '.join(formatted)}")
        else:
            print(f"⚠️ {repo_name}: No local branches found.")


def git_push_current_command(remote="origin"):
    """
    Push the current branch to the same branch name on the specified remote
    across all repositories in src/.
    """
    base_directory = g.script_directory or os.getcwd()
    repo_paths = _find_src_git_repos(base_directory)

    if not repo_paths:
        print("No Git repositories found in 'src'.")
        return

    print(f"Pushing current branches to remote '{remote}' across repositories in 'src'...")
    for repo_path in repo_paths:
        repo_name = os.path.basename(repo_path)

        current_branch = _run_git_command(
            ["git", "symbolic-ref", "--short", "HEAD"], repo_path
        )
        if not current_branch:
            print(f"⚠️ {repo_name}: Detached HEAD or unable to detect current branch. Skipping.")
            continue

        # Verify remote exists
        remote_check = _run_git_command(["git", "remote", "get-url", remote], repo_path)
        if remote_check is None:
            print(f"⚠️ {repo_name}: Remote '{remote}' not found. Skipping.")
            continue

        result = _run_git_command(
            ["git", "push", remote, f"{current_branch}:{current_branch}"], repo_path
        )
        if result is None:
            print(f"❌ {repo_name}: Push failed.")
        else:
            message = result.splitlines()[-1] if result else "Push completed."
            print(f"✅ {repo_name}: {message}")
