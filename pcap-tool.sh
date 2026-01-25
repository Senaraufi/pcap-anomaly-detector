#!/bin/bash

# PCAP Anomaly Detector - Professional Security Tool Interface
# Author: Senaraufi
# Version: 1.0.0

# Colors for professional terminal output
BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
LIGHT_RED='\033[1;31m'
LIGHT_GREEN='\033[1;32m'
LIGHT_BLUE='\033[1;34m'
LIGHT_PURPLE='\033[1;35m'
LIGHT_CYAN='\033[1;36m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'
NC='\033[0m' # No Color

# Project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"

# Tool configuration
TOOL_NAME="PCAP Anomaly Detector"
TOOL_VERSION="v1.0.0"
AUTHOR="Senaraufi"
LOGO_WIDTH=60

# Function to clear screen and show header
show_header() {
    clear
    echo -e "${CYAN}╔$(printf '═%.0s' $(seq 1 $LOGO_WIDTH))╗${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}$(printf "%-*s" $((LOGO_WIDTH-2)) " ")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}$(printf "%*s" $((LOGO_WIDTH/2-8)) "SECURITY ANALYSIS TOOL")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}$(printf "%-*s" $((LOGO_WIDTH-2)) " ")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${LIGHT_CYAN}$(printf "%*s" $((LOGO_WIDTH/2-12)) "$TOOL_NAME")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}$(printf "%-*s" $((LOGO_WIDTH-2)) " ")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${GRAY}$(printf "%*s" $((LOGO_WIDTH/2-15)) "$TOOL_VERSION | $AUTHOR")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}$(printf "%-*s" $((LOGO_WIDTH-2)) " ")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚$(printf '═%.0s' $(seq 1 $LOGO_WIDTH))╝${NC}"
    echo ""
}

# Function to show loading animation
show_loading() {
    local text="$1"
    local duration=${2:-2}
    
    echo -e "${YELLOW}⏳ $text${NC}"
    for i in $(seq 1 $duration); do
        echo -n "${YELLOW}█${NC}"
        sleep 0.3
    done
    echo -e " ${GREEN}✓${NC}"
    echo ""
}

# Function to check and setup environment
setup_environment() {
    echo -e "${LIGHT_BLUE}[ENVIRONMENT CHECK]${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 50))${NC}"
    
    # Check virtual environment
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${YELLOW}⚠ Virtual environment not found${NC}"
        echo -e "${BLUE}→ Creating secure environment...${NC}"
        python3 -m venv "$VENV_DIR" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Environment secured${NC}"
        else
            echo -e "${RED}✗ Failed to create environment${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}✓ Virtual environment found${NC}"
    fi
    
    # Activate environment
    source "$VENV_DIR/bin/activate" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Environment activated${NC}"
    else
        echo -e "${RED}✗ Failed to activate environment${NC}"
        return 1
    fi
    
    # Check dependencies
    pip install -r requirements.txt > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Dependencies verified${NC}"
    else
        echo -e "${RED}✗ Dependency check failed${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ System ready${NC}"
    echo ""
}

# Function to show main menu
show_main_menu() {
    echo -e "${LIGHT_PURPLE}[MAIN MENU]${NC}"
    echo -e "${GRAY}$(printf '═%.0s' $(seq 1 50))${NC}"
    echo ""
    echo -e "${WHITE}1.${NC} ${LIGHT_GREEN}Quick Analysis${NC}           ${GRAY}Fast scan with basic detection${NC}"
    echo -e "${WHITE}2.${NC} ${LIGHT_GREEN}Advanced Analysis${NC}        ${GRAY}Comprehensive security scan${NC}"
    echo -e "${WHITE}3.${NC} ${LIGHT_GREEN}Domain Analysis${NC}          ${GRAY}Focus on suspicious domains${NC}"
    echo -e "${WHITE}4.${NC} ${LIGHT_GREEN}Traffic Analysis${NC}         ${GRAY}Analyze traffic patterns${NC}"
    echo -e "${WHITE}5.${NC} ${LIGHT_GREEN}Malware Detection${NC}        ${GRAY}Scan for malware indicators${NC}"
    echo -e "${WHITE}6.${NC} ${LIGHT_GREEN}Exfiltration Check${NC}        ${GRAY}Detect data theft attempts${NC}"
    echo -e "${WHITE}7.${NC} ${LIGHT_GREEN}Network Anomalies${NC}        ${GRAY}Find unusual network activity${NC}"
    echo -e "${WHITE}8.${NC} ${LIGHT_BLUE}File Information${NC}          ${GRAY}Show PCAP file details${NC}"
    echo -e "${WHITE}9.${NC} ${LIGHT_PURPLE}Test with Sample${NC}         ${GRAY}Run analysis on test data${NC}"
    echo -e "${WHITE}10.${NC} ${LIGHT_CYAN}System Status${NC}            ${GRAY}Check tool configuration${NC}"
    echo ""
    echo -e "${WHITE}0.${NC} ${RED}Exit${NC}                      ${GRAY}Terminate session${NC}"
    echo ""
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 50))${NC}"
}

# Function to get user input with prompt
get_input() {
    local prompt="$1"
    local default="$2"
    local input
    
    echo -ne "${CYAN}$prompt${NC}"
    if [ -n "$default" ]; then
        echo -ne " ${GRAY}[$default]${NC}"
    fi
    echo -ne ": "
    read input
    
    # Clean input - remove any prompt text that might have been captured
    input=$(echo "$input" | sed 's/→.*Select option.*//' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
    
    if [ -z "$input" ] && [ -n "$default" ]; then
        echo "$default"
    else
        echo "$input"
    fi
}

# Function to select PCAP file
select_pcap_file() {
    echo -e "${LIGHT_BLUE}[FILE SELECTION]${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 50))${NC}"
    
    # List available PCAP files
    local pcap_files=($(ls *.pcap 2>/dev/null))
    
    if [ ${#pcap_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}⚠ No PCAP files found in current directory${NC}"
        echo -e "${BLUE}→ Please provide file path:${NC}"
        local file_path=$(get_input "Enter PCAP file path" "")
        
        if [ ! -f "$file_path" ]; then
            echo -e "${RED}✗ File not found: $file_path${NC}"
            return 1
        fi
        
        echo "$file_path"
        return 0
    fi
    
    echo -e "${WHITE}Available PCAP files:${NC}"
    for i in "${!pcap_files[@]}"; do
        local size=$(du -h "${pcap_files[$i]}" | cut -f1)
        echo -e "${WHITE}$((i+1)).${NC} ${LIGHT_GREEN}${pcap_files[$i]}${NC} ${GRAY}($size)${NC}"
    done
    
    echo ""
    local choice=$(get_input "Select file [1-${#pcap_files[@]}]" "1")
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#pcap_files[@]} ]; then
        local selected_file="${pcap_files[$((choice-1))]}"
        echo -e "${GREEN}✓ Selected: $selected_file${NC}"
        echo "$selected_file"
        return 0
    else
        echo -e "${RED}✗ Invalid selection${NC}"
        return 1
    fi
}

# Function to run analysis with progress
run_analysis() {
    local analysis_type="$1"
    local pcap_file="$2"
    local extra_args="$3"
    
    echo -e "${LIGHT_BLUE}[ANALYSIS IN PROGRESS]${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 50))${NC}"
    echo -e "${WHITE}Target:${NC} ${LIGHT_GREEN}$pcap_file${NC}"
    echo -e "${WHITE}Mode:${NC} ${LIGHT_CYAN}$analysis_type${NC}"
    echo ""
    
    # Show analysis progress
    echo -e "${YELLOW}🔍 Initializing analysis engine...${NC}"
    sleep 0.5
    echo -e "${YELLOW}📊 Parsing PCAP data...${NC}"
    sleep 0.5
    echo -e "${YELLOW}🔍 Scanning for threats...${NC}"
    sleep 0.5
    echo -e "${YELLOW}📈 Analyzing patterns...${NC}"
    sleep 0.5
    echo -e "${YELLOW}🛡️ Applying security rules...${NC}"
    sleep 0.5
    echo ""
    
    # Run the actual analysis
    echo -e "${CYAN}Executing security scan...${NC}"
    echo ""
    
    case "$analysis_type" in
        "Quick Analysis")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$pcap_file']$extra_args)"
            ;;
        "Advanced Analysis")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$pcap_file', '--advanced']$extra_args)"
            ;;
        "Domain Analysis")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$pcap_file', '--domains-only']$extra_args)"
            ;;
        "Traffic Analysis")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$pcap_file', '--traffic-only']$extra_args)"
            ;;
        "Malware Detection")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$pcap_file', '--malware-only']$extra_args)"
            ;;
        "Exfiltration Check")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$pcap_file', '--exfil-only']$extra_args)"
            ;;
        "Network Anomalies")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$pcap_file', '--anomaly-only']$extra_args)"
            ;;
        "File Information")
            python -c "from pcap_analyzer.cli import cli; cli(['info', '$pcap_file']$extra_args)"
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}✓ Analysis completed${NC}"
}

# Function to show system status
show_system_status() {
    echo -e "${LIGHT_BLUE}[SYSTEM STATUS]${NC}"
    echo -e "${GRAY}$(printf '═%.0s' $(seq 1 50))${NC}"
    
    echo -e "${WHITE}Tool Version:${NC} ${LIGHT_GREEN}$TOOL_VERSION${NC}"
    echo -e "${WHITE}Python Version:${NC} $(python3 --version 2>/dev/null || echo "Not found")"
    echo -e "${WHITE}Environment:${NC} $([ -d "$VENV_DIR" ] && echo "${GREEN}Active${NC}" || echo "${RED}Inactive${NC}")"
    echo -e "${WHITE}Dependencies:${NC} $([ -f "requirements.txt" ] && echo "${GREEN}Available${NC}" || echo "${RED}Missing${NC}")"
    
    echo ""
    echo -e "${WHITE}Available PCAP files:${NC}"
    local pcap_count=$(ls *.pcap 2>/dev/null | wc -l)
    if [ "$pcap_count" -gt 0 ]; then
        echo -e "${GREEN}✓ $pcap_count files found${NC}"
        ls -la *.pcap 2>/dev/null | head -5
    else
        echo -e "${YELLOW}⚠ No PCAP files found${NC}"
    fi
    
    echo ""
    echo -e "${WHITE}Recent Results:${NC}"
    local result_files=($(ls results*.txt analysis*.txt advanced*.txt 2>/dev/null))
    if [ ${#result_files[@]} -gt 0 ]; then
        echo -e "${GREEN}✓ ${#result_files[@]} result files${NC}"
        for file in "${result_files[@]:0:3}"; do
            local size=$(du -h "$file" 2>/dev/null | cut -f1)
            echo -e "  ${LIGHT_CYAN}• $file${NC} ${GRAY}($size)${NC}"
        done
    else
        echo -e "${YELLOW}⚠ No result files found${NC}"
    fi
}

# Function to handle menu choice
handle_menu_choice() {
    local choice="$1"
    
    case "$choice" in
        1)
            echo -e "${LIGHT_GREEN}[QUICK ANALYSIS]${NC}"
            local pcap_file=$(select_pcap_file)
            if [ $? -eq 0 ]; then
                local save_output=$(get_input "Save results to file" "n")
                local extra_args=""
                if [[ "$save_output" =~ ^[Yy]$ ]]; then
                    local filename=$(get_input "Output filename" "quick_analysis_$(date +%Y%m%d_%H%M%S).txt")
                    extra_args=", '--output', '$filename'"
                fi
                run_analysis "Quick Analysis" "$pcap_file" "$extra_args"
            fi
            ;;
        2)
            echo -e "${LIGHT_GREEN}[ADVANCED ANALYSIS]${NC}"
            local pcap_file=$(select_pcap_file)
            if [ $? -eq 0 ]; then
                local save_output=$(get_input "Save results to file" "y")
                local verbose=$(get_input "Verbose output" "n")
                local extra_args=""
                if [[ "$save_output" =~ ^[Yy]$ ]]; then
                    local filename=$(get_input "Output filename" "advanced_analysis_$(date +%Y%m%d_%H%M%S).txt")
                    extra_args=", '--output', '$filename'"
                fi
                if [[ "$verbose" =~ ^[Yy]$ ]]; then
                    extra_args="$extra_args, '--verbose'"
                fi
                run_analysis "Advanced Analysis" "$pcap_file" "$extra_args"
            fi
            ;;
        3)
            echo -e "${LIGHT_GREEN}[DOMAIN ANALYSIS]${NC}"
            local pcap_file=$(select_pcap_file)
            if [ $? -eq 0 ]; then
                run_analysis "Domain Analysis" "$pcap_file" ""
            fi
            ;;
        4)
            echo -e "${LIGHT_GREEN}[TRAFFIC ANALYSIS]${NC}"
            local pcap_file=$(select_pcap_file)
            if [ $? -eq 0 ]; then
                run_analysis "Traffic Analysis" "$pcap_file" ""
            fi
            ;;
        5)
            echo -e "${LIGHT_GREEN}[MALWARE DETECTION]${NC}"
            local pcap_file=$(select_pcap_file)
            if [ $? -eq 0 ]; then
                run_analysis "Malware Detection" "$pcap_file" ""
            fi
            ;;
        6)
            echo -e "${LIGHT_GREEN}[EXFILTRATION CHECK]${NC}"
            local pcap_file=$(select_pcap_file)
            if [ $? -eq 0 ]; then
                run_analysis "Exfiltration Check" "$pcap_file" ""
            fi
            ;;
        7)
            echo -e "${LIGHT_GREEN}[NETWORK ANOMALIES]${NC}"
            local pcap_file=$(select_pcap_file)
            if [ $? -eq 0 ]; then
                run_analysis "Network Anomalies" "$pcap_file" ""
            fi
            ;;
        8)
            echo -e "${LIGHT_BLUE}[FILE INFORMATION]${NC}"
            local pcap_file=$(select_pcap_file)
            if [ $? -eq 0 ]; then
                run_analysis "File Information" "$pcap_file" ""
            fi
            ;;
        9)
            echo -e "${LIGHT_PURPLE}[TEST WITH SAMPLE]${NC}"
            if [ ! -f "test_traffic.pcap" ]; then
                echo -e "${YELLOW}Creating test file...${NC}"
                python test_sample.py
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✓ Test file created${NC}"
                else
                    echo -e "${RED}✗ Failed to create test file${NC}"
                    return
                fi
            fi
            run_analysis "Advanced Analysis" "test_traffic.pcap" ""
            ;;
        10)
            show_system_status
            ;;
        0)
            echo -e "${RED}[SESSION TERMINATED]${NC}"
            echo -e "${GRAY}Thank you for using $TOOL_NAME${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}✗ Invalid choice: $choice${NC}"
            echo -e "${YELLOW}Please select a valid option (0-10)${NC}"
            ;;
    esac
}

# Function to pause and wait for user
pause_for_user() {
    echo ""
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# Main program loop
main() {
    # Setup environment first
    if ! setup_environment; then
        echo -e "${RED}✗ Failed to setup environment${NC}"
        exit 1
    fi
    
    # Main menu loop
    while true; do
        show_header
        show_main_menu
        local choice=$(get_input "Select option" "")
        
        echo ""
        handle_menu_choice "$choice"
        
        if [ "$choice" != "0" ]; then
            pause_for_user
        fi
    done
}

# Start the program
main "$@"
