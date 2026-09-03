"""
Docker client service for Agent Manager Plugin.

Provides functions for container discovery, recreation, state checking,
and docker-compose operations following the Container Recreation Approach
from the migration plan.
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Any

import aiodocker

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# SCL Label constants for container discovery
SCL_LABEL_PLUGIN = "scl.plugin"
SCL_LABEL_TOPOLOGY = "scl.topology"
SCL_LABEL_NETWORK = "scl.network"
SCL_LABEL_HOST = "scl.host"
SCL_LABEL_HOST_TYPE = "scl.host_type"
SCL_LABEL_HAS_AGENTS = "scl.has_agents"

# Expected plugin label value
SCL_PLUGIN_NETWORK_TOPOLOGY = "network-topology"

# Container state polling intervals
CONTAINER_STATE_POLL_INTERVAL = 0.5  # seconds
OPENCODE_READY_TIMEOUT = 30  # seconds
CONTAINER_RECREATE_TIMEOUT = 60  # seconds

# SCL shared network name — must match the value in SCL's docker-compose.yml
SCL_NETWORK_NAME = os.getenv("SCL_NETWORK_NAME", "playground-net")

# OpenCode configuration
OPENCODE_PORT = int(os.getenv("OPENCODE_PORT", "4096"))
OPENCODE_HEALTH_PATH = "/global/health"
OPENCODE_READY_INDICATORS = [
    "OpenCode server ready",
    "OpenCode server is ready",
    "OpenCode serve started",
    "Listening on port",
    "Server started",
    "opencode serve started"
]


# =============================================================================
# Enums
# =============================================================================

class ContainerState(str, Enum):
    """Docker container states."""
    RUNNING = "running"
    STOPPED = "stopped"
    PAUSED = "paused"
    RESTARTING = "restarting"
    EXITED = "exited"
    DEAD = "dead"
    REMOVING = "removing"
    RECREATING = "recreating"


class DockerComposeError(Exception):
    """Exception raised for docker-compose operation failures."""
    pass


class ContainerNotFoundError(Exception):
    """Exception raised when a container cannot be found."""
    pass


class ContainerRecreationError(Exception):
    """Exception raised when container recreation fails."""
    pass


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ContainerInfo:
    """Information about a discovered container."""
    container_id: str
    container_name: str
    topology_id: str
    network_id: str
    host_id: str
    host_name: str
    host_type: str
    ip_address: Optional[str]
    image: str
    state: ContainerState
    current_agents: List[str]
    can_assign_agent: bool
    opencode_ready: bool
    opencode_port: int
    labels: Dict[str, str]
    ports: Dict[str, Any]
    created: str
    status: str


@dataclass
class ContainerDetails:
    """Detailed information about a container."""
    id: str
    name: str
    image: str
    state: ContainerState
    status: str
    created: str
    labels: Dict[str, str]
    ports: Dict[str, Any]
    mounts: List[Dict[str, Any]]
    ip_address: Optional[str]
    network: Optional[str]
    health: Optional[Dict[str, Any]]
    opencode_ready: bool
    opencode_port_exposed: bool


# =============================================================================
# Docker Client Class
# =============================================================================

class DockerClient:
    """Async Docker client wrapper with SCL-specific operations."""

    def __init__(self):
        """Initialize the Docker client."""
        self._docker: Optional[aiodocker.Docker] = None

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def connect(self) -> None:
        """Establish connection to Docker daemon."""
        if self._docker is None:
            self._docker = aiodocker.Docker()
            logger.info("Connected to Docker daemon")

    async def close(self) -> None:
        """Close Docker connection."""
        if self._docker:
            await self._docker.close()
            self._docker = None
            logger.info("Closed Docker connection")

    @property
    def docker(self) -> aiodocker.Docker:
        """Get the Docker client instance, connecting if needed."""
        if self._docker is None:
            raise RuntimeError("Docker client not connected. Call connect() first.")
        return self._docker


# =============================================================================
# Container Discovery Functions
# =============================================================================

async def list_containers(
    docker_client: DockerClient,
    topology_id: Optional[str] = None,
    network_id: Optional[str] = None,
    host_id: Optional[str] = None,
    state: Optional[ContainerState] = None,
    has_agents: Optional[bool] = None
) -> List[ContainerInfo]:
    """List containers with SCL labels, optionally filtered.

    Args:
        docker_client: Connected Docker client instance
        topology_id: Filter by topology ID
        network_id: Filter by network ID
        host_id: Filter by host ID
        state: Filter by container state
        has_agents: Filter by whether container has agents assigned

    Returns:
        List of ContainerInfo objects matching filters

    Raises:
        RuntimeError: If Docker client is not connected
    """
    containers = await docker_client.docker.containers.list(all=True)

    result = []
    for container in containers:
        # Get container details
        container_dict = await container.show()
        labels = container_dict.get('Config', {}).get('Labels', {})

        # Filter for SCL topology containers
        if labels.get(SCL_LABEL_PLUGIN) != SCL_PLUGIN_NETWORK_TOPOLOGY:
            continue

        # Apply filters
        if topology_id and labels.get(SCL_LABEL_TOPOLOGY) != topology_id:
            continue
        if network_id and labels.get(SCL_LABEL_NETWORK) != network_id:
            continue
        if host_id and labels.get(SCL_LABEL_HOST) != host_id:
            continue
        if has_agents is not None:
            has_agents_value = labels.get(SCL_LABEL_HAS_AGENTS, "false").lower() == "true"
            if has_agents != has_agents_value:
                continue

        # Extract container state
        container_state = _parse_container_state(container_dict)

        if state and container_state != state:
            continue

        # Get IP address from container networks
        ip_address = _extract_container_ip(container_dict)

        # Parse current agents from label
        current_agents = _parse_agents_label(labels.get("scl.agents", ""))

        # Check if OpenCode is ready
        opencode_ready = await check_opencode_ready(docker_client, container_dict['Id'])

        # Build container info
        info = ContainerInfo(
            container_id=container_dict['Id'],
            container_name=container_dict['Name'].lstrip('/'),
            topology_id=labels.get(SCL_LABEL_TOPOLOGY, ""),
            network_id=labels.get(SCL_LABEL_NETWORK, ""),
            host_id=labels.get(SCL_LABEL_HOST, ""),
            host_name=labels.get("scl.host_name", ""),
            host_type=labels.get(SCL_LABEL_HOST_TYPE, "server"),
            ip_address=ip_address,
            image=container_dict['Config']['Image'],
            state=container_state,
            current_agents=current_agents,
            can_assign_agent=True,  # All SCL hosts can have agents via recreation
            opencode_ready=opencode_ready,
            opencode_port=OPENCODE_PORT,
            labels=labels,
            ports=_parse_container_ports(container_dict),
            created=container_dict['Created'],
            status=container_dict.get('State', {}).get('Status', 'unknown')
        )

        result.append(info)

    logger.debug(f"Discovered {len(result)} SCL containers with filters: "
                 f"topology={topology_id}, network={network_id}, host={host_id}, "
                 f"state={state}, has_agents={has_agents}")

    return result


async def get_container_details(
    docker_client: DockerClient,
    container_id: str
) -> ContainerDetails:
    """Get detailed information about a specific container.

    Args:
        docker_client: Connected Docker client instance
        container_id: Container ID or name

    Returns:
        ContainerDetails object with comprehensive container information

    Raises:
        ContainerNotFoundError: If container does not exist
    """
    try:
        container = await docker_client.docker.containers.get(container_id)
        container_dict = await container.show()
    except aiodocker.exceptions.DockerError as e:
        if "404" in str(e):
            raise ContainerNotFoundError(f"Container {container_id} not found")
        raise

    labels = container_dict.get('Config', {}).get('Labels', {})
    state = _parse_container_state(container_dict)

    # Check OpenCode readiness
    opencode_ready = await check_opencode_ready(docker_client, container_id)
    opencode_port_exposed = _is_opencode_port_exposed(container_dict)

    # Get health status if available
    health = container_dict.get('State', {}).get('Health')

    return ContainerDetails(
        id=container_dict['Id'],
        name=container_dict['Name'].lstrip('/'),
        image=container_dict['Config']['Image'],
        state=state,
        status=container_dict.get('State', {}).get('Status', 'unknown'),
        created=container_dict['Created'],
        labels=labels,
        ports=_parse_container_ports(container_dict),
        mounts=container_dict.get('Mounts', []),
        ip_address=_extract_container_ip(container_dict),
        network=_get_primary_network(container_dict),
        health=health,
        opencode_ready=opencode_ready,
        opencode_port_exposed=opencode_port_exposed
    )


# =============================================================================
# Container Recreation Functions (Key Implementation)
# =============================================================================

async def recreate_container(
    docker_client: DockerClient,
    topology_id: str,
    service_name: str,
    compose_project: Optional[str] = None,
    compose_files: Optional[List[str]] = None
) -> str:
    """Recreate a single container using docker-compose.

    This is the core function for the Container Recreation Approach.
    It uses docker-compose up --force-recreate to rebuild only the
    target service/container.

    Args:
        docker_client: Connected Docker client instance
        topology_id: Topology identifier (used as project name)
        service_name: Docker Compose service name to recreate
        compose_project: Optional override for project name
        compose_files: Optional list of docker-compose.yml files

    Returns:
        New container ID after recreation

    Raises:
        ContainerRecreationError: If recreation fails
        DockerComposeError: If docker-compose command fails
    """
    project = compose_project or topology_id

    logger.info(f"Recreating container for service {service_name} in project {project}")

    # Build docker-compose command
    compose_cmd = _build_compose_command(
        compose_files,
        project=project,
        command="up",
        args=["-d", "--force-recreate", "--no-deps", service_name]
    )

    try:
        # Execute docker-compose up --force-recreate
        process = await asyncio.create_subprocess_exec(
            *compose_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=CONTAINER_RECREATE_TIMEOUT
        )

        if process.returncode != 0:
            error_msg = stderr.decode('utf-8', errors='replace')
            raise DockerComposeError(
                f"docker-compose up failed for {service_name}: {error_msg}"
            )

        logger.info(f"Container recreation successful for {service_name}")
        logger.debug(f"Compose output: {stdout.decode('utf-8', errors='replace')}")

        # Get new container ID
        new_container_id = await _get_container_id_for_service(
            docker_client, project, service_name
        )

        if not new_container_id:
            raise ContainerRecreationError(
                f"Failed to find new container ID after recreation for {service_name}"
            )

        logger.info(f"New container ID for {service_name}: {new_container_id}")
        return new_container_id

    except asyncio.TimeoutError:
        raise ContainerRecreationError(
            f"Container recreation timed out after {CONTAINER_RECREATE_TIMEOUT}s"
        )
    except Exception as e:
        raise ContainerRecreationError(f"Failed to recreate container: {str(e)}")


async def docker_compose_up(
    docker_client: DockerClient,
    topology_id: str,
    compose_files: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    force_recreate: bool = False,
    no_deps: bool = False,
    wait: bool = True,
    timeout: int = 60
) -> Dict[str, str]:
    """Execute docker-compose up with options.

    This is a generalized version of docker-compose up that supports
    multiple services and options. Used for bringing up services after
    agent assignment changes.

    Args:
        docker_client: Connected Docker client instance
        topology_id: Topology identifier (used as project name)
        compose_files: Optional list of docker-compose.yml files
        services: Optional list of services to bring up (None = all)
        force_recreate: Whether to use --force-recreate flag
        no_deps: Whether to use --no-deps flag
        wait: Whether to wait for containers to be healthy
        timeout: Maximum time to wait for containers (seconds)

    Returns:
        Dictionary mapping service names to new container IDs

    Raises:
        DockerComposeError: If docker-compose command fails
    """
    args = ["-d"]

    if force_recreate:
        args.append("--force-recreate")
    if no_deps:
        args.append("--no-deps")

    if services:
        args.extend(services)

    compose_cmd = _build_compose_command(
        compose_files,
        project=topology_id,
        command="up",
        args=args
    )

    logger.info(f"Running docker-compose up with args: {args}")

    try:
        process = await asyncio.create_subprocess_exec(
            *compose_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )

        if process.returncode != 0:
            error_msg = stderr.decode('utf-8', errors='replace')
            raise DockerComposeError(f"docker-compose up failed: {error_msg}")

        logger.info("docker-compose up completed successfully")

        # Map services to container IDs
        result = {}
        target_services = services or await _get_all_services(
            docker_client, topology_id, compose_files
        )

        for service in target_services:
            container_id = await _get_container_id_for_service(
                docker_client, topology_id, service
            )
            if container_id:
                result[service] = container_id

        return result

    except asyncio.TimeoutError:
        raise DockerComposeError(f"docker-compose up timed out after {timeout}s")
    except Exception as e:
        raise DockerComposeError(f"Failed to run docker-compose up: {str(e)}")


# =============================================================================
# OpenCode Readiness Functions
# =============================================================================

async def wait_for_opencode(
    docker_client: DockerClient,
    container_id: str,
    timeout: int = OPENCODE_READY_TIMEOUT
) -> bool:
    """Wait for OpenCode server to be ready in a container.

    Polls the container for OpenCode readiness indicators:
    1. HTTP health check on port 4096
    2. Container logs for ready indicators
    3. Container health status (if healthcheck configured)

    Args:
        docker_client: Connected Docker client instance
        container_id: Container ID to check
        timeout: Maximum time to wait (seconds)

    Returns:
        True if OpenCode is ready, False if timeout reached

    Raises:
        ContainerNotFoundError: If container does not exist
    """
    start_time = time.time()

    logger.info(f"Waiting for OpenCode readiness in container {container_id[:12]}")

    try:
        container = await docker_client.docker.containers.get(container_id)
    except aiodocker.exceptions.DockerError:
        raise ContainerNotFoundError(f"Container {container_id} not found")

    while time.time() - start_time < timeout:
        # Check 1: Try HTTP health check
        if await _check_opencode_http(container_id):
            logger.info(f"OpenCode HTTP health check passed for {container_id[:12]}")
            return True

        # Check 2: Look for ready indicators in logs
        if await _check_opencode_logs(container):
            logger.info(f"OpenCode ready indicators found in logs for {container_id[:12]}")
            return True

        # Check 3: Check container health status
        if await _check_container_health(container):
            logger.info(f"Container health check passed for {container_id[:12]}")
            return True

        # Wait before next poll
        await asyncio.sleep(CONTAINER_STATE_POLL_INTERVAL)

    logger.warning(f"OpenCode not ready in container {container_id[:12]} after {timeout}s")
    return False


async def check_opencode_ready(
    docker_client: DockerClient,
    container_id: str
) -> bool:
    """Check if OpenCode server is ready in a container (non-blocking).

    Performs a single check without waiting.

    Args:
        docker_client: Connected Docker client instance
        container_id: Container ID to check

    Returns:
        True if OpenCode appears ready, False otherwise
    """
    try:
        # Quick HTTP check
        if await _check_opencode_http(container_id):
            return True

        # Quick log check (last 50 lines)
        container = await docker_client.docker.containers.get(container_id)
        logs = await container.log(stderr=True, stdout=True, tail=50)

        if logs:
            log_text = ''.join(logs)
            return any(indicator in log_text for indicator in OPENCODE_READY_INDICATORS)

        return False

    except (aiodocker.exceptions.DockerError, asyncio.TimeoutError):
        return False


# =============================================================================
# Container State Checking Functions
# =============================================================================

async def get_container_state(
    docker_client: DockerClient,
    container_id: str
) -> ContainerState:
    """Get the current state of a container.

    Args:
        docker_client: Connected Docker client instance
        container_id: Container ID to check

    Returns:
        ContainerState enum value

    Raises:
        ContainerNotFoundError: If container does not exist
    """
    try:
        container = await docker_client.docker.containers.get(container_id)
        container_dict = await container.show()
        return _parse_container_state(container_dict)
    except aiodocker.exceptions.DockerError as e:
        if "404" in str(e):
            raise ContainerNotFoundError(f"Container {container_id} not found")
        raise


async def is_container_running(
    docker_client: DockerClient,
    container_id: str
) -> bool:
    """Check if a container is currently running.

    Args:
        docker_client: Connected Docker client instance
        container_id: Container ID to check

    Returns:
        True if running, False otherwise
    """
    try:
        state = await get_container_state(docker_client, container_id)
        return state == ContainerState.RUNNING
    except ContainerNotFoundError:
        return False


async def is_container_healthy(
    docker_client: DockerClient,
    container_id: str
) -> bool:
    """Check if a container is healthy (has passing healthcheck).

    Args:
        docker_client: Connected Docker client instance
        container_id: Container ID to check

    Returns:
        True if healthy, False if unhealthy or no healthcheck
    """
    try:
        container = await docker_client.docker.containers.get(container_id)
        container_dict = await container.show()
        health = container_dict.get('State', {}).get('Health')

        if not health:
            return False

        return health.get('Status') == 'healthy'
    except (aiodocker.exceptions.DockerError, KeyError):
        return False


async def wait_for_container_state(
    docker_client: DockerClient,
    container_id: str,
    desired_state: ContainerState,
    timeout: int = 30
) -> bool:
    """Wait for a container to reach a desired state.

    Args:
        docker_client: Connected Docker client instance
        container_id: Container ID to monitor
        desired_state: State to wait for
        timeout: Maximum time to wait (seconds)

    Returns:
        True if desired state reached, False if timeout
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            current_state = await get_container_state(docker_client, container_id)
            if current_state == desired_state:
                return True
        except ContainerNotFoundError:
            if desired_state == ContainerState.REMOVING:
                return True
            return False

        await asyncio.sleep(CONTAINER_STATE_POLL_INTERVAL)

    return False


async def get_container_logs(
    docker_client: DockerClient,
    container_id: str,
    tail: Optional[int] = None,
    since: Optional[str] = None,
    follow: bool = False
) -> str:
    """Get logs from a container.

    Args:
        docker_client: Connected Docker client instance
        container_id: Container ID to get logs from
        tail: Number of lines from end of log
        since: Timestamp to get logs since
        follow: Whether to follow logs (returns async generator)

    Returns:
        Log output as string

    Raises:
        ContainerNotFoundError: If container does not exist
    """
    try:
        container = await docker_client.docker.containers.get(container_id)

        if follow:
            # Return async generator for streaming
            return container.log(stdout=True, stderr=True, follow=True, tail=tail)

        logs = await container.log(stdout=True, stderr=True, tail=tail, since=since)
        return ''.join(logs)

    except aiodocker.exceptions.DockerError as e:
        if "404" in str(e):
            raise ContainerNotFoundError(f"Container {container_id} not found")
        raise


async def execute_in_container(
    docker_client: DockerClient,
    container_id: str,
    command: List[str],
    workdir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: int = 30
) -> Dict[str, Any]:
    """Execute a command inside a container.

    Args:
        docker_client: Connected Docker client instance
        container_id: Container ID to execute in
        command: Command as list of strings
        workdir: Working directory inside container
        env: Environment variables for command
        timeout: Maximum time to wait (seconds)

    Returns:
        Dictionary with exit_code, stdout, stderr

    Raises:
        ContainerNotFoundError: If container does not exist
        asyncio.TimeoutError: If command times out
    """
    try:
        container = await docker_client.docker.containers.get(container_id)

        create_kwargs = {
            "cmd": command,
            "attach_stdout": True,
            "attach_stderr": True
        }

        if workdir:
            create_kwargs["workdir"] = workdir

        if env:
            create_kwargs["env"] = [f"{k}={v}" for k, v in env.items()]

        exec_instance = await container.exec(**create_kwargs)

        # Wait for execution with timeout
        result = await asyncio.wait_for(
            exec_instance.start(detach=False),
            timeout=timeout
        )

        return {
            "exit_code": result[0],
            "stdout": result[1],
            "stderr": result[2]
        }

    except asyncio.TimeoutError:
        raise
    except aiodocker.exceptions.DockerError as e:
        if "404" in str(e):
            raise ContainerNotFoundError(f"Container {container_id} not found")
        raise


# =============================================================================
# Docker Compose Helper Functions
# =============================================================================

def _build_compose_command(
    compose_files: Optional[List[str]] = None,
    project: Optional[str] = None,
    command: str = "up",
    args: Optional[List[str]] = None
) -> List[str]:
    """Build a docker-compose command as a list of strings.

    Args:
        compose_files: List of docker-compose.yml files to use
        project: Project name
        command: docker-compose command (up, down, ps, etc.)
        args: Additional arguments for the command

    Returns:
        List of command components ready for subprocess execution
    """
    cmd = ["docker", "compose"]

    if compose_files:
        for compose_file in compose_files:
            cmd.extend(["-f", compose_file])

    if project:
        cmd.extend(["-p", project])

    cmd.append(command)

    if args:
        cmd.extend(args)

    return cmd


async def _get_container_id_for_service(
    docker_client: DockerClient,
    project: str,
    service_name: str
) -> Optional[str]:
    """Get the current container ID for a docker-compose service.

    Args:
        docker_client: Connected Docker client instance
        project: Docker Compose project name
        service_name: Service name to look up

    Returns:
        Container ID or None if not found
    """
    try:
        # List all containers with the project label
        containers = await docker_client.docker.containers.list(
            all=True,
            filters={"label": [f"com.docker.compose.project={project}"]}
        )

        for container in containers:
            container_dict = await container.show()
            labels = container_dict.get('Config', {}).get('Labels', {})

            # Check if this container matches the service
            if labels.get('com.docker.compose.service') == service_name:
                return container_dict['Id']

        return None

    except Exception as e:
        logger.error(f"Error getting container ID for {service_name}: {e}")
        return None


async def _get_all_services(
    docker_client: DockerClient,
    project: str,
    compose_files: Optional[List[str]] = None
) -> List[str]:
    """Get all service names from a docker-compose project.

    Args:
        docker_client: Connected Docker client instance
        project: Docker Compose project name
        compose_files: Optional compose files to parse

    Returns:
        List of service names
    """
    services = set()

    # Method 1: Parse compose files if provided
    if compose_files:
        for compose_file in compose_files:
            try:
                with open(compose_file, 'r') as f:
                    compose_config = json.load(f) if compose_file.endswith('.json') else {}
                    if compose_config.get('services'):
                        services.update(compose_config['services'].keys())
            except Exception as e:
                logger.debug(f"Could not parse {compose_file}: {e}")

    # Method 2: Query running containers
    try:
        containers = await docker_client.docker.containers.list(
            all=True,
            filters={"label": [f"com.docker.compose.project={project}"]}
        )

        for container in containers:
            container_dict = await container.show()
            labels = container_dict.get('Config', {}).get('Labels', {})
            service = labels.get('com.docker.compose.service')
            if service:
                services.add(service)

    except Exception as e:
        logger.debug(f"Error getting services from containers: {e}")

    return list(services)


# =============================================================================
# OpenCode Check Helper Functions
# =============================================================================

async def _check_opencode_http(container_id: str) -> bool:
    """Check if OpenCode HTTP endpoint is responding.

    Args:
        container_id: Container ID

    Returns:
        True if HTTP health check passes
    """
    try:
        # Get container's IP or use localhost if port mapped
        # For simplicity, we'll try to execute curl inside the container
        process = await asyncio.create_subprocess_exec(
            "docker", "exec", container_id,
            "curl", "-f", f"http://localhost:{OPENCODE_PORT}{OPENCODE_HEALTH_PATH}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=5
            )
        except asyncio.TimeoutError:
            # wait_for cancels communicate() but leaves the docker-exec child
            # running. Kill it or every timed-out probe leaks a process (and
            # its ThreadedChildWatcher thread) until the host is drained.
            process.kill()
            await process.wait()
            return False

        return process.returncode == 0

    except (asyncio.TimeoutError, FileNotFoundError, ProcessLookupError):
        return False


async def _check_opencode_logs(container) -> bool:
    """Check container logs for OpenCode readiness indicators.

    Args:
        container: Docker container object

    Returns:
        True if ready indicators found in logs
    """
    try:
        logs = await container.log(stderr=True, stdout=True, tail=100)
        if not logs:
            return False

        log_text = ''.join(logs)
        return any(indicator in log_text for indicator in OPENCODE_READY_INDICATORS)

    except Exception:
        return False


async def _check_container_health(container) -> bool:
    """Check if container's healthcheck is passing.

    Args:
        container: Docker container object

    Returns:
        True if health status is healthy
    """
    try:
        container_dict = await container.show()
        health = container_dict.get('State', {}).get('Health')

        if not health:
            return False

        return health.get('Status') == 'healthy'

    except Exception:
        return False


# =============================================================================
# Container Parsing Helper Functions
# =============================================================================

def _parse_container_state(container_dict: Dict[str, Any]) -> ContainerState:
    """Parse container state from Docker API response.

    Args:
        container_dict: Container dictionary from Docker API

    Returns:
        ContainerState enum value
    """
    state_info = container_dict.get('State', {})
    status = state_info.get('Status', '').lower()
    running = state_info.get('running', False)
    paused = state_info.get('Paused', False)
    restarting = state_info.get('Restarting', False)
    dead = state_info.get('Dead', False)

    if dead:
        return ContainerState.DEAD
    if restarting:
        return ContainerState.RESTARTING
    if paused:
        return ContainerState.PAUSED
    if running:
        return ContainerState.RUNNING
    if status == 'exited':
        return ContainerState.EXITED
    if status == 'removing':
        return ContainerState.REMOVING

    # Default to status string if no match
    try:
        return ContainerState(status)
    except ValueError:
        return ContainerState.EXITED


def _extract_container_ip(container_dict: Dict[str, Any]) -> Optional[str]:
    """Extract the primary IP address from container network settings.

    Args:
        container_dict: Container dictionary from Docker API

    Returns:
        IP address string or None
    """
    networks = container_dict.get('NetworkSettings', {}).get('Networks', {})

    if SCL_NETWORK_NAME in networks:
        return networks[SCL_NETWORK_NAME].get('IPAddress')

    for network_info in networks.values():
        if network_info.get('IPAddress'):
            return network_info['IPAddress']

    return None


def _get_primary_network(container_dict: Dict[str, Any]) -> Optional[str]:
    """Get the primary network name for a container.

    Args:
        container_dict: Container dictionary from Docker API

    Returns:
        Network name or None
    """
    networks = container_dict.get('NetworkSettings', {}).get('Networks', {})

    if SCL_NETWORK_NAME in networks:
        return SCL_NETWORK_NAME

    return next(iter(networks.keys()), None)


def _parse_container_ports(container_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Parse port bindings from container.

    Args:
        container_dict: Container dictionary from Docker API

    Returns:
        Dictionary of port bindings
    """
    ports_info = container_dict.get('NetworkSettings', {}).get('Ports', {})
    result = {}

    for port_spec, bindings in ports_info.items():
        if bindings:
            result[port_spec] = [
                {
                    'host_ip': b.get('HostIp', '0.0.0.0'),
                    'host_port': b.get('HostPort', '')
                }
                for b in bindings
            ]
        else:
            result[port_spec] = []

    return result


def _parse_agents_label(agents_label: str) -> List[str]:
    """Parse the scl.agents label into a list of agent types.

    Args:
        agents_label: Comma-separated agent types string

    Returns:
        List of agent type strings
    """
    if not agents_label:
        return []

    return [agent.strip() for agent in agents_label.split(',') if agent.strip()]


def _is_opencode_port_exposed(container_dict: Dict[str, Any]) -> bool:
    """Check if OpenCode port is exposed in the container.

    Args:
        container_dict: Container dictionary from Docker API

    Returns:
        True if port 4096 is exposed
    """
    ports = container_dict.get('NetworkSettings', {}).get('Ports', {})

    # Check for various port specifications
    port_specs = [
        f"{OPENCODE_PORT}/tcp",
        f"{OPENCODE_PORT}/udp",
        str(OPENCODE_PORT)
    ]

    for spec in port_specs:
        if spec in ports:
            return True

    return False


# =============================================================================
# Utility Functions
# =============================================================================

async def get_service_name_from_host_id(
    docker_client: DockerClient,
    topology_id: str,
    host_id: str
) -> Optional[str]:
    """Get the docker-compose service name for a host ID.

    In SCL topology, service names follow the pattern:
    {topology_id}_{network_id}_{host_name}

    This function queries Docker to find the matching service.

    Args:
        docker_client: Connected Docker client instance
        topology_id: Topology identifier
        host_id: Host ID to find

    Returns:
        Service name or None if not found
    """
    try:
        containers = await list_containers(
            docker_client,
            topology_id=topology_id
        )

        for container in containers:
            if container.host_id == host_id:
                # Extract service name from container name
                # Container name: {project}-{service}-1-{hash}
                parts = container.container_name.split('-')
                if len(parts) >= 2:
                    # Remove project prefix and instance suffix
                    # Assuming project name doesn't contain hyphens
                    # This is a simplified approach
                    return '-'.join(parts[1:-1]) or container.container_name

        return None

    except Exception as e:
        logger.error(f"Error getting service name for host {host_id}: {e}")
        return None


async def get_container_by_host_id(
    docker_client: DockerClient,
    topology_id: str,
    host_id: str
) -> Optional[str]:
    """Get container ID for a specific host ID.

    Args:
        docker_client: Connected Docker client instance
        topology_id: Topology identifier
        host_id: Host ID to look up

    Returns:
        Container ID or None if not found
    """
    try:
        containers = await list_containers(
            docker_client,
            topology_id=topology_id,
            host_id=host_id
        )

        if containers:
            return containers[0].container_id

        return None

    except Exception as e:
        logger.error(f"Error getting container for host {host_id}: {e}")
        return None


# =============================================================================
# Module Initialization
# =============================================================================

def create_docker_client() -> DockerClient:
    """Factory function to create a Docker client instance.

    Returns:
        New DockerClient instance

    Example:
        async with create_docker_client() as docker:
            containers = await list_containers(docker)
    """
    return DockerClient()
