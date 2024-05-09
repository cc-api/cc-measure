#!/bin/bash

set -e

WORK_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
VENV=${WORK_DIR}/venv

# Install python virtual environment
sudo apt-get install -y python3-virtualenv

# Create virtual environment
if [ -d "$VENV" ]; then
    # If the directory exists, delete it
    echo "=====> Deleting $VENV."
    rm -r "$VENV"
fi

echo "=====> Creating $VENV."
virtualenv ${VENV}
source ${VENV}/bin/activate

# Install cc-measure and dependencies
pip3 install -r requirements.txt
python3 setup.py bdist_wheel
pip3 install dist/*.whl --force-reinstall
