#! /usr/bin/env bash

echo "* Creating virtual environment..."
python -m venv persons_venv
echo "* Done."
source persons_venv/bin/activate
echo "* Virtual environment activated."
echo "* Installing dependencies..."
pip install faker bcrypt &> /dev/null && {
  echo "* Done."
  echo "* Building database..."
  python fixtures.py
  echo "* Done."
}
deactivate
rm -r persons_venv
