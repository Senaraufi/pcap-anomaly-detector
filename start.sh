#!/bin/bash

# PCAP Anomaly Detector - Start Script
# Author: Senaraufi
# Description: Easy launcher for the PCAP analysis tool

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}    PCAP Anomaly Detector Launcher    ${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Function to check if virtual environment exists
check_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${YELLOW}Virtual environment not found. Creating one...${NC}"
        python3 -m venv "$VENV_DIR"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Virtual environment created${NC}"
        else
            echo -e "${RED}✗ Failed to create virtual environment${NC}"
            exit 1
        fi
    fi
}

# Function to activate virtual environment
activate_venv() {
    source "$VENV_DIR/bin/activate"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Virtual environment activated${NC}"
    else
        echo -e "${RED}✗ Failed to activate virtual environment${NC}"
        exit 1
    fi
}

# Function to install dependencies
install_deps() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    pip install -r requirements.txt > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Dependencies installed${NC}"
    else
        echo -e "${RED}✗ Failed to install dependencies${NC}"
        exit 1
    fi
}

# Function to show help
show_help() {
    echo -e "${CYAN}Usage: $0 [OPTION] [PCAP_FILE]${NC}"
    echo ""
    echo -e "${YELLOW}OPTIONS:${NC}"
    echo "  info <file>              Show PCAP file information"
    echo "  analyze <file>           Run basic analysis"
    echo "  advanced <file>          Run advanced analysis (recommended)"
    echo "  domains <file>           Only analyze suspicious domains"
    echo "  traffic <file>            Only analyze traffic spikes"
    echo "  exfil <file>             Only analyze data exfiltration"
    echo "  malware <file>            Only analyze malware indicators"
    echo "  anomalies <file>          Only analyze network anomalies"
    echo "  test                     Run with test file"
    echo "  setup                    Setup environment only"
    echo "  help                     Show this help message"
    echo ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo "  $0 advanced traffic.pcap"
    echo "  $0 info suspicious_traffic.pcap"
    echo "  $0 test"
    echo ""
    echo -e "${YELLOW}OUTPUT OPTIONS:${NC}"
    echo "  Add '--output filename.txt' to save results"
    echo "  Add '--verbose' for detailed logging"
    echo ""
    echo -e "${YELLOW}ADVANCED EXAMPLES:${NC}"
    echo "  $0 advanced traffic.pcap --output report.txt --verbose"
    echo "  $0 malware suspicious.pcap --output malware_report.txt"
}

# Function to run analysis
run_analysis() {
    local command="$1"
    local pcap_file="$2"
    shift 2
    local extra_args=""
    
    # Build extra arguments string
    while [ $# -gt 0 ]; do
        if [ "$1" == "--output" ] || [ "$1" == "--verbose" ]; then
            extra_args="$extra_args, '$1'"
            shift
            if [ $# -gt 0 ]; then
                extra_args="$extra_args, '$2'"
                shift
            fi
        else
            extra_args="$extra_args, '$1'"
            shift
        fi
    done
    
    if [ ! -f "$pcap_file" ]; then
        echo -e "${RED}✗ PCAP file not found: $pcap_file${NC}"
        echo -e "${YELLOW}Available files in directory:${NC}"
        ls -la *.pcap 2>/dev/null || echo -e "${YELLOW}No .pcap files found${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Analyzing: $pcap_file${NC}"
    echo -e "${BLUE}Command: $command${NC}"
    if [ -n "$extra_args" ]; then
        echo -e "${BLUE}Extra args: $extra_args${NC}"
    fi
    echo ""
    
    # Run the analysis
    if [ -n "$extra_args" ]; then
        python -c "from pcap_analyzer.cli import cli; cli(['$command', '$pcap_file'$extra_args])"
    else
        python -c "from pcap_analyzer.cli import cli; cli(['$command', '$pcap_file'])"
    fi
}

# Function to run test
run_test() {
    echo -e "${BLUE}Running analysis with test file...${NC}"
    
    if [ ! -f "test_traffic.pcap" ]; then
        echo -e "${YELLOW}Creating test file...${NC}"
        python test_sample.py
        if [ $? -ne 0 ]; then
            echo -e "${RED}✗ Failed to create test file${NC}"
            exit 1
        fi
    fi
    
    run_analysis "analyze" "test_traffic.pcap" "--advanced"
}

# Main execution
main() {
    case "${1:-help}" in
        "setup")
            echo -e "${BLUE}Setting up environment...${NC}"
            check_venv
            activate_venv
            install_deps
            echo -e "${GREEN}✓ Setup complete! Ready to use.${NC}"
            ;;
        "info")
            if [ -z "$2" ]; then
                echo -e "${RED}✗ Please provide a PCAP file${NC}"
                show_help
                exit 1
            fi
            check_venv
            activate_venv
            install_deps
            run_analysis "info" "$2" "$@"
            ;;
        "analyze")
            if [ -z "$2" ]; then
                echo -e "${RED}✗ Please provide a PCAP file${NC}"
                show_help
                exit 1
            fi
            check_venv
            activate_venv
            install_deps
            run_analysis "analyze" "$2" "$@"
            ;;
        "advanced")
            if [ -z "$2" ]; then
                echo -e "${RED}✗ Please provide a PCAP file${NC}"
                show_help
                exit 1
            fi
            check_venv
            activate_venv
            install_deps
            run_analysis "analyze" "$2" "--advanced"
            ;;
        "domains")
            if [ -z "$2" ]; then
                echo -e "${RED}✗ Please provide a PCAP file${NC}"
                show_help
                exit 1
            fi
            check_venv
            activate_venv
            install_deps
            run_analysis "analyze" "$2" "--domains-only" "$@"
            ;;
        "traffic")
            if [ -z "$2" ]; then
                echo -e "${RED}✗ Please provide a PCAP file${NC}"
                show_help
                exit 1
            fi
            check_venv
            activate_venv
            install_deps
            run_analysis "analyze" "$2" "--traffic-only" "$@"
            ;;
        "exfil")
            if [ -z "$2" ]; then
                echo -e "${RED}✗ Please provide a PCAP file${NC}"
                show_help
                exit 1
            fi
            check_venv
            activate_venv
            install_deps
            run_analysis "analyze" "$2" "--exfil-only" "$@"
            ;;
        "malware")
            if [ -z "$2" ]; then
                echo -e "${RED}✗ Please provide a PCAP file${NC}"
                show_help
                exit 1
            fi
            check_venv
            activate_venv
            install_deps
            run_analysis "analyze" "$2" "--malware-only" "$@"
            ;;
        "anomalies")
            if [ -z "$2" ]; then
                echo -e "${RED}✗ Please provide a PCAP file${NC}"
                show_help
                exit 1
            fi
            check_venv
            activate_venv
            install_deps
            run_analysis "analyze" "$2" "--anomaly-only" "$@"
            ;;
        "test")
            check_venv
            activate_venv
            install_deps
            run_test
            ;;
        "help"|*)
            show_help
            ;;
    esac
}

# Run main function with all arguments
main "$@"
