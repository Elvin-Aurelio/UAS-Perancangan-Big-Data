# Paket Dataset UAS Praktik

Tema: Data Science, Data Discovery, Data Security dengan simulasi streaming data.

Cara menjalankan generator:
```bash
python stream_generator.py --events 100000 --speed 0.05 --out stream_events.jsonl
```

Mahasiswa dapat memakai `sample_stream_events.csv` sebagai batch data dan `stream_generator.py` untuk simulasi streaming.

## Realtime Alert di Terminal
Untuk menjalankan monitoring alert realtime di terminal, gunakan `stream_processor.py` yang mengambil event dari `stream_generator.py`:
```bash
python stream_processor.py --events 1000 --speed 0.05
```

## Dashboard Interaktif
Jalankan dashboard Streamlit untuk monitoring alert realtime:
```bash
streamlit run app.py
```
