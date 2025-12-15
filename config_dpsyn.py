# path related constant
from pathlib import Path

PROJECT_PATH = str(Path(__file__).resolve().parent) + "/"
RAW_DATA_PATH = PROJECT_PATH + "lib_preprocess/temp_data/raw_data/"
PROCESSED_DATA_PATH = PROJECT_PATH + "lib_preprocess/temp_data/processed_data/"
SYNTHESIZED_RECORDS_PATH = PROJECT_PATH + "lib_preprocess/temp_data/synthesized_records/"
MARGINAL_PATH = PROJECT_PATH + "lib_preprocess/temp_data/marginal/"
DEPENDENCY_PATH = PROJECT_PATH + 'lib_preprocess/temp_data/dependency/'

ALL_PATH = [RAW_DATA_PATH, PROCESSED_DATA_PATH, SYNTHESIZED_RECORDS_PATH, MARGINAL_PATH, DEPENDENCY_PATH]


# config file path
TYPE_CONFIG_PATH = PROJECT_PATH + "fields.json"
MARGINAL_INIT = [('srcport', 'proto', 'flag'), ('dstport', 'proto', 'flag')]
