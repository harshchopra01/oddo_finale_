import os
import glob
import logging
from dotenv import load_dotenv
load_dotenv(override=True)

# document loader and splitter

from langchain.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter

# azure components

from langchain_openai import AzureOpenAIEmbeddings
from langchain_community.vectorstores import AzureSearch

# stepup logging
logging.basicConfig(
    level = logging.INFO,
    format = '%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("indexer")

def index_docs():
    '''
    Reads pdf and chunks them and uploads them into azure search vector store
    '''
    
    # define paths,we looks for the data folder
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_folder = os.path.join(current_dir, "../../backend/data")
    
    # check the env variables
    
    logger.info("="*60)
    logger.info("Environment variables checks:")
    logger.info(f"AZURE_OPENAI_ENDPOINT: {os.getenv('AZURE_OPENAI_ENDPOINT')}")
    logger.info(f"AZURE_OPENAI_API_VERSION: {os.getenv('AZURE_OPENAI_API_VERSION')}")
    logger.info(f"Embedding Deployment: {os.getenv('AZURE_OPENAI_EMBEDDING_DEPLOYMENT')}")
    logger.info(f"AZURE_SEARCH_ENDPOINT: {os.getenv('AZURE_SEARCH_ENDPOINT')}")
    logger.info(f"AZURE_SEARCH_INDEX_NAME: {os.getenv('AZURE_SEARCH_INDEX_NAME')}")
    logger.info("="*60)
    
    
    # validate the required env
    required_env_vars = [
        'AZURE_OPENAI_ENDPOINT',
        'AZURE_OPENAI_API_KEY',
        'AZURE_SEARCH_API_KEY',
        'AZURE_SEARCH_ENDPOINT',
        'AZURE_SEARCH_INDEX_NAME'
    ]
    
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        logger.error(f"Missing required environment variables: {missing_vars}")
        return 
    
    # intialize the embedding model
    
    try:
        logger.info("Intializing Azure OpenAI Embeddings for vector store ... ")
        embeddings = AzureOpenAIEmbeddings(
            azure_search_endpoint=os.getenv('AZURE_SEARCH_ENDPOINT'),
            azure_search_key = os.getenv('AZURE_SEARCH_API_KEY'),
            index_name = index_name,
            embedding_function = embeddings.
        )
        
        logger.info("Azure OpenAI Embeddings intialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing Azure OpenAI Embeddings: {e}")
        logger.error("Failed to initialize Azure OpenAI Embeddings. Please check your environment variables and try again.")
        return
    
    