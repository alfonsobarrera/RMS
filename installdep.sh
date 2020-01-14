cat requirements.txt | while read line; do
python -m pip install "$line"
done