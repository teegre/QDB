#! /usr/bin/env bash

echo "* Creating virtual environment..."
python -m venv persons_test_venv
echo "* Done."
source persons_test_venv/bin/activate
echo "* Virtual environment activated."
echo "* Installing dependencies..."
pip install pytest &> /dev/null && {
  echo "* Done."
  pytest tests/get_refs_test.py
  echo "* Done."
}
deactivate
rm -r persons_test_venv

