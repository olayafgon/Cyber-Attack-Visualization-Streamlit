PYTHON ?= python3

DATA_SOURCES := kev epss hibp ransomwhere eurepoc vcdb nvd

.PHONY: clean data-all data-verify preprocess preprocess-verify figures app palette $(addprefix data-,$(DATA_SOURCES))

# Borra solo lo regenerable; conserva los .parquet, que son parte de la entrega.
clean:
	find src app -name "__pycache__" -type d -exec rm -rf {} +
	rm -rf data/processed/preview .ipynb_checkpoints

data-all:
	$(PYTHON) -m src.acquisition.download --source all

$(addprefix data-,$(DATA_SOURCES)): data-%:
	$(PYTHON) -m src.acquisition.download --source $*

data-verify:
	$(PYTHON) -m src.acquisition.verify

preprocess:
	$(PYTHON) -m src.preprocessing.run

preprocess-verify:
	$(PYTHON) -m src.preprocessing.verify

figures:
	$(PYTHON) -m src.visualization.export

app:
	$(PYTHON) -m streamlit run app/app.py

palette:
	$(PYTHON) -m src.visualization.palette_check

# Comandos personales
-include author.mk
