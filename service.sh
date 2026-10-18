#!/usr/bin/env bash
# ==============================================================================
# WhyYouKnow Service Manager (service.sh)
# Controls Backend (FastAPI/Uvicorn) and Frontend (Vite/React)
# Usage: ./service.sh {start|stop|restart|status|logs} [all|backend|frontend]
# ==============================================================================

set -e

# Base directories
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$ROOT_DIR/.run"
LOG_DIR="$ROOT_DIR/logs"

# Ensure runtime directories exist
mkdir -p "$PID_DIR" "$LOG_DIR"

# Ports and Hosts (respects cloud environment $PORT and $HOST)
BACKEND_PORT="${BACKEND_PORT:-${PORT:-8000}}"
BACKEND_HOST="${BACKEND_HOST:-${HOST:-0.0.0.0}}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
FRONTEND_HOST="${FRONTEND_HOST:-${HOST:-0.0.0.0}}"

# PIDs and Logs
BACKEND_PID_FILE="$PID_DIR/backend.pid"
FRONTEND_PID_FILE="$PID_DIR/frontend.pid"
BACKEND_LOG="$LOG_DIR/backend.log"
FRONTEND_LOG="$LOG_DIR/frontend.log"

# Executable paths
PYTHON_VENV="$ROOT_DIR/server/.venv"
UVICORN_BIN="$PYTHON_VENV/bin/uvicorn"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

is_pid_running() {
    local pid="$1"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    return 1
}

get_process_pid_by_file() {
    local pid_file="$1"
    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null || true)
        if [ -n "$pid" ] && is_pid_running "$pid"; then
            echo "$pid"
            return 0
        else
            # Stale PID file, remove it
            rm -f "$pid_file"
        fi
    fi
    echo ""
    return 1
}

get_pids_by_port() {
    local port="$1"
    # Try ss, lsof, or fuser to detect listening processes on the port
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn "sport = :$port" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d'=' -f2 | sort -u
    elif command -v lsof >/dev/null 2>&1; then
        lsof -ti :"$port" 2>/dev/null || true
    elif command -v fuser >/dev/null 2>&1; then
        fuser "$port/tcp" 2>/dev/null || true
    fi
}

# ------------------------------------------------------------------------------
# Pre-flight Checks
# ------------------------------------------------------------------------------

check_prerequisites() {
    # Check .env
    if [ ! -f "$ROOT_DIR/.env" ]; then
        print_warning "No .env file found at $ROOT_DIR/.env. Copying from example if available..."
        if [ -f "$ROOT_DIR/.env.example" ]; then
            cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
            print_info "Created .env from .env.example"
        fi
    fi

    # Check Backend venv
    if [ ! -x "$UVICORN_BIN" ]; then
        print_error "Uvicorn executable not found at $UVICORN_BIN"
        print_info "Please set up the Python virtual environment first:"
        print_info "  python3 -m venv server/.venv && server/.venv/bin/pip install -r server/requirements.txt"
        exit 1
    fi

    # Check Frontend node_modules
    if [ ! -d "$ROOT_DIR/node_modules" ]; then
        print_warning "node_modules directory not found. Running 'npm install'..."
        (cd "$ROOT_DIR" && npm install)
    fi
}

# ------------------------------------------------------------------------------
# Start Services
# ------------------------------------------------------------------------------

start_backend() {
    echo -e "${BOLD}Starting Backend (FastAPI / Uvicorn)...${NC}"
    local existing_pid
    existing_pid=$(get_process_pid_by_file "$BACKEND_PID_FILE" || true)

    if [ -n "$existing_pid" ]; then
        print_warning "Backend is already running (PID: $existing_pid)"
        return 0
    fi

    # Check if port is already in use by another process
    local port_pids
    port_pids=$(get_pids_by_port "$BACKEND_PORT")
    if [ -n "$port_pids" ]; then
        print_error "Port $BACKEND_PORT is already in use by PID(s): $port_pids"
        print_info "Please stop the existing process or run './service.sh stop' first."
        return 1
    fi

    # Launch uvicorn in background
    setsid "$UVICORN_BIN" main:app \
        --app-dir "$ROOT_DIR/server" \
        --host "$BACKEND_HOST" \
        --port "$BACKEND_PORT" \
        < /dev/null >> "$BACKEND_LOG" 2>&1 &

    local new_pid=$!
    disown "$new_pid" 2>/dev/null || true
    echo "$new_pid" > "$BACKEND_PID_FILE"

    # Verify launch
    sleep 1.5
    if is_pid_running "$new_pid"; then
        print_success "Backend started successfully! (PID: $new_pid)"
        print_info "API URL: http://localhost:$BACKEND_PORT"
        print_info "Log file: $BACKEND_LOG"
    else
        print_error "Backend failed to start. Last log entries:"
        tail -n 15 "$BACKEND_LOG"
        rm -f "$BACKEND_PID_FILE"
        return 1
    fi
}

start_frontend() {
    echo -e "${BOLD}Starting Frontend (Vite Dev Server)...${NC}"
    local existing_pid
    existing_pid=$(get_process_pid_by_file "$FRONTEND_PID_FILE" || true)

    if [ -n "$existing_pid" ]; then
        print_warning "Frontend is already running (PID: $existing_pid)"
        return 0
    fi

    # Check if port is already in use by another process
    local port_pids
    port_pids=$(get_pids_by_port "$FRONTEND_PORT")
    if [ -n "$port_pids" ]; then
        print_error "Port $FRONTEND_PORT is already in use by PID(s): $port_pids"
        print_info "Please stop the existing process or run './service.sh stop' first."
        return 1
    fi

    # Launch vite in background directly from project root
    cd "$ROOT_DIR"
    setsid npx vite --host "$FRONTEND_HOST" --port "$FRONTEND_PORT" \
        < /dev/null >> "$FRONTEND_LOG" 2>&1 &

    local new_pid=$!
    disown "$new_pid" 2>/dev/null || true
    echo "$new_pid" > "$FRONTEND_PID_FILE"

    # Verify launch
    sleep 1.5
    if is_pid_running "$new_pid"; then
        print_success "Frontend started successfully! (PID: $new_pid)"
        print_info "Web App URL: http://localhost:$FRONTEND_PORT"
        print_info "Log file: $FRONTEND_LOG"
    else
        print_error "Frontend failed to start. Last log entries:"
        tail -n 15 "$FRONTEND_LOG"
        rm -f "$FRONTEND_PID_FILE"
        return 1
    fi
}

start_all() {
    local target="${1:-all}"
    check_prerequisites

    case "$target" in
        backend)
            start_backend
            ;;
        frontend)
            start_frontend
            ;;
        all|"")
            start_backend
            echo ""
            start_frontend
            echo ""
            print_success "All services are running!"
            print_info "Frontend: http://localhost:$FRONTEND_PORT"
            print_info "Backend:  http://localhost:$BACKEND_PORT"
            ;;
        *)
            print_error "Unknown target: $target. Available targets: all, backend, frontend"
            exit 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Stop Services
# ------------------------------------------------------------------------------

stop_service_process() {
    local name="$1"
    local pid_file="$2"
    local port="$3"

    echo -e "${BOLD}Stopping $name...${NC}"
    local pid=""
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file" 2>/dev/null || true)
    fi

    # If PID file exists and process is alive
    if [ -n "$pid" ] && is_pid_running "$pid"; then
        print_info "Sending SIGTERM to $name (PID: $pid)..."
        kill -15 "$pid" 2>/dev/null || true

        # Wait up to 5 seconds
        local count=0
        while is_pid_running "$pid" && [ "$count" -lt 10 ]; do
            sleep 0.5
            count=$((count + 1))
        done

        if is_pid_running "$pid"; then
            print_warning "$name did not stop gracefully. Sending SIGKILL..."
            kill -9 "$pid" 2>/dev/null || true
            sleep 0.5
        fi
        print_success "$name stopped."
    else
        print_info "$name is not running according to PID file."
    fi

    rm -f "$pid_file"

    # Also clean up any lingering processes on the port
    if [ -n "$port" ]; then
        local lingering_pids
        lingering_pids=$(get_pids_by_port "$port")
        if [ -n "$lingering_pids" ]; then
            print_warning "Found lingering process on port $port (PIDs: $lingering_pids). Terminating..."
            for lp in $lingering_pids; do
                kill -15 "$lp" 2>/dev/null || true
            done
            sleep 0.5
            for lp in $lingering_pids; do
                if is_pid_running "$lp"; then
                    kill -9 "$lp" 2>/dev/null || true
                fi
            done
            print_success "Freed port $port."
        fi
    fi
}

stop_all() {
    local target="${1:-all}"
    case "$target" in
        backend)
            stop_service_process "Backend" "$BACKEND_PID_FILE" "$BACKEND_PORT"
            ;;
        frontend)
            stop_service_process "Frontend" "$FRONTEND_PID_FILE" "$FRONTEND_PORT"
            ;;
        all|"")
            stop_service_process "Frontend" "$FRONTEND_PID_FILE" "$FRONTEND_PORT"
            echo ""
            stop_service_process "Backend" "$BACKEND_PID_FILE" "$BACKEND_PORT"
            echo ""
            print_success "All services stopped."
            ;;
        *)
            print_error "Unknown target: $target. Available targets: all, backend, frontend"
            exit 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Status
# ------------------------------------------------------------------------------

show_status() {
    echo -e "${BOLD}=== WhyYouKnow Service Status ===${NC}"
    echo ""

    # Backend
    local b_pid
    b_pid=$(get_process_pid_by_file "$BACKEND_PID_FILE" || true)
    local b_port_pids
    b_port_pids=$(get_pids_by_port "$BACKEND_PORT")

    if [ -n "$b_pid" ]; then
        echo -e "  Backend  (FastAPI):  ${GREEN}RUNNING${NC} (PID: $b_pid, Port: $BACKEND_PORT)"
        # Health check
        local health_res=""
        if command -v curl >/dev/null 2>&1; then
            health_res=$(curl -s -m 2 "http://localhost:$BACKEND_PORT/api/health" 2>/dev/null || true)
            if [[ "$health_res" == *"ok"* ]]; then
                echo -e "    Health check:      ${GREEN}OK${NC} (http://localhost:$BACKEND_PORT/api/health)"
            else
                echo -e "    Health check:      ${YELLOW}Unresponsive${NC}"
            fi
        fi
    elif [ -n "$b_port_pids" ]; then
        echo -e "  Backend  (FastAPI):  ${YELLOW}PORT IN USE${NC} (Port: $BACKEND_PORT by PID: $b_port_pids, but not tracked by service.sh)"
    else
        echo -e "  Backend  (FastAPI):  ${RED}STOPPED${NC}"
    fi

    echo ""

    # Frontend
    local f_pid
    f_pid=$(get_process_pid_by_file "$FRONTEND_PID_FILE" || true)
    local f_port_pids
    f_port_pids=$(get_pids_by_port "$FRONTEND_PORT")

    if [ -n "$f_pid" ]; then
        echo -e "  Frontend (Vite):     ${GREEN}RUNNING${NC} (PID: $f_pid, Port: $FRONTEND_PORT)"
        echo -e "    URL:               ${CYAN}http://localhost:$FRONTEND_PORT${NC}"
    elif [ -n "$f_port_pids" ]; then
        echo -e "  Frontend (Vite):     ${YELLOW}PORT IN USE${NC} (Port: $FRONTEND_PORT by PID: $f_port_pids, but not tracked by service.sh)"
    else
        echo -e "  Frontend (Vite):     ${RED}STOPPED${NC}"
    fi

    echo ""
    echo -e "Logs:"
    echo -e "  Backend:  $BACKEND_LOG"
    echo -e "  Frontend: $FRONTEND_LOG"
}

# ------------------------------------------------------------------------------
# Logs
# ------------------------------------------------------------------------------

show_logs() {
    local target="${1:-all}"
    case "$target" in
        backend)
            print_info "Tailing Backend logs ($BACKEND_LOG)... (Press Ctrl+C to exit)"
            tail -n 50 -f "$BACKEND_LOG"
            ;;
        frontend)
            print_info "Tailing Frontend logs ($FRONTEND_LOG)... (Press Ctrl+C to exit)"
            tail -n 50 -f "$FRONTEND_LOG"
            ;;
        all|"")
            print_info "Showing last 25 lines of Backend and Frontend logs..."
            echo -e "\n${BOLD}=== Backend Log ($BACKEND_LOG) ===${NC}"
            tail -n 25 "$BACKEND_LOG" 2>/dev/null || echo "No backend log yet."
            echo -e "\n${BOLD}=== Frontend Log ($FRONTEND_LOG) ===${NC}"
            tail -n 25 "$FRONTEND_LOG" 2>/dev/null || echo "No frontend log yet."
            ;;
        *)
            print_error "Unknown log target: $target. Choose from: backend, frontend, all"
            exit 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------

ACTION="${1:-}"
TARGET="${2:-all}"

case "$ACTION" in
    start)
        start_all "$TARGET"
        ;;
    stop)
        stop_all "$TARGET"
        ;;
    restart)
        print_info "Restarting services ($TARGET)..."
        stop_all "$TARGET"
        sleep 1
        start_all "$TARGET"
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$TARGET"
        ;;
    help|--help|-h|"")
        echo -e "${BOLD}Usage:${NC} $0 {start|stop|restart|status|logs} [all|backend|frontend]"
        echo ""
        echo "Commands:"
        echo "  start [target]    Start services (default: all)"
        echo "  stop [target]     Stop services (default: all)"
        echo "  restart [target]  Restart services (default: all)"
        echo "  status            Show status and health check"
        echo "  logs [target]     Display or tail logs (all|backend|frontend)"
        echo ""
        echo "Targets:"
        echo "  all               Both Backend (port 8000) and Frontend (port 5173)"
        echo "  backend           Only FastAPI backend"
        echo "  frontend          Only Vite frontend"
        echo ""
        echo "Examples:"
        echo "  ./service.sh start"
        echo "  ./service.sh stop"
        echo "  ./service.sh restart"
        echo "  ./service.sh status"
        echo "  ./service.sh logs backend"
        ;;
    *)
        print_error "Unknown command: $ACTION"
        echo "Run '$0 help' for usage instructions."
        exit 1
        ;;
esac
