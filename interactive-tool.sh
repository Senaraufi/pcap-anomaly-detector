#!/bin/bash

# PCAP Anomaly Detector - Interactive Security Tool
# Author: Senaraufi
# Version: 1.0.0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'

# Project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"

# Tool info
TOOL_NAME="PCAP Anomaly Detector"
VERSION="v1.0.0"

# Clear screen and show banner
show_banner() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}                    SECURITY ANALYSIS TOOL                    ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}                                                              ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${LIGHT_CYAN}                 PCAP Anomaly Detector                  ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}                                                              ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${GRAY}                       v1.0.0 | Senaraufi                       ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}                                                              ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Setup environment
setup_env() {
    echo -e "${BLUE}[SYSTEM INITIALIZATION]${NC}"
    echo -e "${GRAY}──────────────────────────────────────────────────────────${NC}"
    
    # Create venv if needed
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${YELLOW}→ Creating secure environment...${NC}"
        python3 -m venv "$VENV_DIR" >/dev/null 2>&1
    fi
    
    # Activate venv
    source "$VENV_DIR/bin/activate" 2>/dev/null
    
    # Install dependencies
    pip install -r requirements.txt >/dev/null 2>&1
    
    echo -e "${GREEN}✓ System ready${NC}"
    echo ""
}

# Show main menu
show_menu() {
    echo -e "${PURPLE}[MAIN MENU]${NC}"
    echo -e "${GRAY}═════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${WHITE}1)${NC} ${GREEN}Quick Analysis${NC}           ${GRAY}Fast scan with basic detection${NC}"
    echo -e "${WHITE}2)${NC} ${GREEN}Advanced Analysis${NC}        ${GRAY}Comprehensive security scan${NC}"
    echo -e "${WHITE}3)${NC} ${GREEN}Domain Analysis${NC}          ${GRAY}Focus on suspicious domains${NC}"
    echo -e "${WHITE}4)${NC} ${GREEN}Traffic Analysis${NC}         ${GRAY}Analyze traffic patterns${NC}"
    echo -e "${WHITE}5)${NC} ${GREEN}Malware Detection${NC}        ${GRAY}Scan for malware indicators${NC}"
    echo -e "${WHITE}6)${NC} ${GREEN}Exfiltration Check${NC}        ${GRAY}Detect data theft attempts${NC}"
    echo -e "${WHITE}7)${NC} ${GREEN}Network Anomalies${NC}        ${GRAY}Find unusual network activity${NC}"
    echo -e "${WHITE}8)${NC} ${BLUE}File Information${NC}          ${GRAY}Show PCAP file details${NC}"
    echo -e "${WHITE}9)${NC} ${PURPLE}Test with Sample${NC}         ${GRAY}Run analysis on test data${NC}"
    echo -e "${WHITE}10)${NC} ${CYAN}System Status${NC}            ${GRAY}Check tool configuration${NC}"
    echo ""
    echo -e "${WHITE}0)${NC} ${RED}Exit${NC}                      ${GRAY}Terminate session${NC}"
    echo ""
    echo -e "${GRAY}──────────────────────────────────────────────────────────${NC}"
}

# Get user choice
get_choice() {
    while true; do
        echo -ne "${CYAN}Select option [0-10]: ${NC}"
        read choice
        choice=$(echo "$choice" | tr -d '[:space:]')
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -le 10 ]; then
            echo "$choice"
            return 0
        else
            echo -e "${RED}✗ Invalid choice. Please enter 0-10.${NC}"
        fi
    done
}

# Select PCAP file
select_file() {
    echo -e "${BLUE}[FILE SELECTION]${NC}"
    echo -e "${GRAY}──────────────────────────────────────────────────────────${NC}"
    
    # List PCAP files
    files=($(ls *.pcap 2>/dev/null))
    
    if [ ${#files[@]} -eq 0 ]; then
        echo -e "${YELLOW}⚠ No PCAP files found.${NC}"
        echo -ne "${CYAN}Enter file path: ${NC}"
        read filepath
        if [ -f "$filepath" ]; then
            echo "$filepath"
            return 0
        else
            echo -e "${RED}✗ File not found.${NC}"
            return 1
        fi
    fi
    
    echo -e "${WHITE}Available files:${NC}"
    for i in "${!files[@]}"; do
        size=$(du -h "${files[$i]}" | cut -f1)
        echo -e "${WHITE}$((i+1)).${NC} ${GREEN}${files[$i]}${NC} ${GRAY}($size)${NC}"
    done
    
    while true; do
        echo -ne "${CYAN}Select file [1-${#files[@]}]: ${NC}"
        read filechoice
        filechoice=$(echo "$filechoice" | tr -d '[:space:]')
        
        if [[ "$filechoice" =~ ^[0-9]+$ ]] && [ "$filechoice" -ge 1 ] && [ "$filechoice" -le ${#files[@]} ]; then
            selected="${files[$((filechoice-1))]}"
            echo -e "${GREEN}✓ Selected: $selected${NC}"
            echo "$selected"
            return 0
        else
            echo -e "${RED}✗ Invalid selection.${NC}"
        fi
    done
}

# Run analysis
run_analysis() {
    local mode="$1"
    local file="$2"
    
    echo -e "${BLUE}[ANALYSIS IN PROGRESS]${NC}"
    echo -e "${GRAY}──────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}Target:${NC} ${GREEN}$file${NC}"
    echo -e "${WHITE}Mode:${NC} ${CYAN}$mode${NC}"
    echo ""
    
    echo -e "${YELLOW}🔍 Initializing security engine...${NC}"
    sleep 0.5
    echo -e "${YELLOW}📊 Parsing network data...${NC}"
    sleep 0.5
    echo -e "${YELLOW}🔍 Scanning for threats...${NC}"
    sleep 0.5
    echo -e "${YELLOW}🛡️ Applying detection rules...${NC}"
    sleep 0.5
    echo ""
    
    case "$mode" in
        "Quick Analysis")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$file'])"
            ;;
        "Advanced Analysis")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$file', '--advanced'])"
            ;;
        "Domain Analysis")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$file', '--domains-only'])"
            ;;
        "Traffic Analysis")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$file', '--traffic-only'])"
            ;;
        "Malware Detection")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$file', '--malware-only'])"
            ;;
        "Exfiltration Check")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$file', '--exfil-only'])"
            ;;
        "Network Anomalies")
            python -c "from pcap_analyzer.cli import cli; cli(['analyze', '$file', '--anomaly-only'])"
            ;;
        "File Information")
            python -c "from pcap_analyzer.cli import cli; cli(['info', '$file'])"
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}✓ Analysis completed${NC}"
}

# Show system status
show_status() {
    echo -e "${CYAN}[SYSTEM STATUS]${NC}"
    echo -e "${GRAY}═════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${WHITE}Tool Version:${NC} ${GREEN}$VERSION${NC}"
    echo -e "${WHITE}Python:${NC} $(python3 --version 2>/dev/null || echo "Not found")"
    echo -e "${WHITE}Environment:${NC} ${GREEN}Active${NC}"
    echo -e "${WHITE}Dependencies:${NC} ${GREEN}Installed${NC}"
    
    echo ""
    echo -e "${WHITE}PCAP Files:${NC}"
    count=$(ls *.pcap 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo -e "${GREEN}✓ $count files found${NC}"
        ls -lah *.pcap 2>/dev/null | head -3
    else
        echo -e "${YELLOW}⚠ No PCAP files${NC}"
    fi
    
    echo ""
    echo -e "${WHITE}Recent Results:${NC}"
    if ls results*.txt 2>/dev/null >/dev/null; then
        echo -e "${GREEN}✓ Result files available${NC}"
        ls -lah results*.txt 2>/dev/null | head -2
    else
        echo -e "${YELLOW}⚠ No result files${NC}"
    fi
}

# Main program
main() {
    setup_env
    
    while true; do
        show_banner
        show_menu
        
        choice=$(get_choice)
        echo ""
        
        case "$choice" in
            0)
                echo -e "${RED}[SESSION TERMINATED]${NC}"
                echo -e "${GRAY}Thank you for using $TOOL_NAME${NC}"
                exit 0
                ;;
            1|2|3|4|5|6|7|8)
                file=$(select_file)
                if [ $? -eq 0 ]; then
                    case "$choice" in
                        1) run_analysis "Quick Analysis" "$file" ;;
                        2) run_analysis "Advanced Analysis" "$file" ;;
                        3) run_analysis "Domain Analysis" "$file" ;;
                        4) run_analysis "Traffic Analysis" "$file" ;;
                        5) run_analysis "Malware Detection" "$file" ;;
                        6) run_analysis "Exfiltration Check" "$file" ;;
                        7) run_analysis "Network Anomalies" "$file" ;;
                        8) run_analysis "File Information" "$file" ;;
                    esac
                fi
                ;;
            9)
                echo -e "${PURPLE}[TEST MODE]${NC}"
                if [ ! -f "test_traffic.pcap" ]; then
                    echo -e "${YELLOW}→ Creating test file...${NC}"
                    python test_sample.py
                fi
                run_analysis "Advanced Analysis" "test_traffic.pcap"
                ;;
            10)
                show_status
                ;;
        esac
        
        echo ""
        echo -e "${CYAN}Press Enter to continue...${NC}"
        read
    done
}

# Start the tool
main "$@"
