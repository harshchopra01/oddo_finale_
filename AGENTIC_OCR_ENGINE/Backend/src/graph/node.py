import json
import os
import logging
import re
from typing import Dict,Any,List
from langchain_openai import AzureChatOpenAI,AzureOpenAIEmbeddings
from langchain_community.vectorstores import AzureSearch
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import BaseMessage,HumanMessage,SystemMessage,AIMessage

# import state schema
from backend.src.graph import VideoAuditState,ComplianceIssue
from backend.src.services.video_indexer import VideoIndexer

# configure logger
logger = logging.getLogger("brand-guardian")
logging.basicConfig(level=logging.INFO)

                    
# NODE 1: Indexer Node : responsible for ingesting the video, extracting metadata, transcript and ocr text, and storing it in the state                    
# respomsible for video to text
def index_video_node(state: VideoAuditState) -> Dict[str,Any]:
    """download the video from the given URL 
    upload to azure video indexer and extracr insights"""
    
    video_url = state.get("video_url")
    video_id = state.get("video_id","video_demo")
    
    logger.info(f"---[Node: Indexer] Starting video indexing for video_id: {video_id} and video_url: {video_url} ---")
    
    local_filename = "temp_audit_video.mp4"
    
    try:
        vi_service = VideoIndexer()
        # if download using yt-dlp
        if "youtube.com" in video_url or "youtu.be" in video_url:
            local_filename = vi_service.download_video(video_url,video_id)
        else:
            raise Exception("provide a valid youtube url for video indexing")
            
        # upload and extract insights
        azure_video_id = vi_service.upload_video(local_filename,video_name = video_id)
        logger.info(f"video uploaded to azure video indexer with id: {azure_video_id}")
        
        # cleanup:
        
        if os.path.exists(local_filename):
            os.remove(local_filename)
            logger.info(f"local video file {local_filename} removed after indexing")
            
        # wait for indexing to complete and get insights
        raw_insights = vi_service.wait_for_processing(azure_video_id)
        
        # extract relevant insights and update state
        clean_data = vi_service.extract_data(raw_insights)
        logger.info(f"video insights extracted")
        return clean_data 
        
    except Exception as e:
        logger.error(f"Video Indexing failed! Error: {str(e)}")
        return {
            "error": [str(e)],
            "final_status":"FAIL",
            "transcript": None,
            "ocr_text": []
        }
        
        
        
# NODE 2: Compliance Checker Node : responsible for checking the compliance of the video content with the given guidelines and updating the state with the compliance results

def audio_content_node(state: VideoAuditState) -> Dict[str,Any]:
    """
    Performs RAG to audit content and analyze the audio content of the video and extract relevant information such as presence of specific keywords, sentiment analysis, etc."""
    
    logger.info(f"---[Node: Audio Content Checker] Starting audio content analysis for video_id: {state.get('video_id')} ---")
    transcript = state.get("transcript","")
    if not transcript:
        logger.warning("No transcript available for audio content analysis")
        return {
            "final_status":"FAIL",
            "final_report":"Audit Skipped because transcript is not available",
            
        }
        
    # initialzing azure client
    llm = AzureChatOpenAI(
        azure_deployment= os.getenv("AZURE_OPENAI_DEPLOYMENT"),
        openai_api_version= os.getenv("AZURE_OPENAI_API_VERSION"),
        temperature=0.0
    )
    
    # embedding for retrieval
    embedding_model = AzureOpenAIEmbeddings(
        azure_deployment = "text-embedding-3-small",
        openai_api_version = os.getenv("AZURE_OPENAI_API_VERSION")
        
    )
    
    # vector store for RAG
    vector_store = AzureSearch(
        azure_search_endpoint = os.getenv("AZURE_SEARCH_ENDPOINT"),
        azure_search_key = os.getenv("AZURE_SEARCH_KEY"),
        azure_search_index = os.getenv("AZURE_SEARCH_INDEX"),
        embedding_function=embedding.embed_query
    )
    
    # RAG 
    
    ocr_text = state.get("ocr_text",[])
    query_text = f"{transcript}{''.join(ocr_text)}"
    
    docs = vector_store.similarity_search(query_text,k=3)
    
    retrieved_rules = "\n\n".join([doc.page_content for doc in docs])
    
    #System prompt
    
    system_prompt = f"""
    you are a senior brand compliance auditor 
    OFFICALLY REGULATORY RULES:
    {retrieved_rules}
    INTRUCTION:
    1. Analyze the transcript and ocr text below.
    2. indentify any violations of the rules.
    3. return strictly JSON in the following format:{{
        "compliance_results":[{{
            "category": "category of the violation based on the rules",
            "severity": "low/medium/high",
            "description": "brief description of the violation",}}],
        "status": "Failed",
        "final_report": "a detailed report of the compliance check"
    }}
    
    if there are no violations, return the following JSON:
    {{
        "compliance_results":[],
        "status": "Passed",
        "final_report": "The video content is compliant with the brand guidelines."
    }}
    """
    
    user_message = f"""
    VIDEO_METADATA: {state.get('video_metadata',{})}
    TRANSCRIPT: {transcript}
    OCR_TEXT: {ocr_text}
    """
    
    
    try:
        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_message)
        ])
        
        content = response.content
        ## cleaning the data
        if "```" in content:
            content = re.search(r"```json(.*?)```",content,re.DOTALL)[0].strip()
        audit_data = json.loads(content.strip())
        
        return{
            "compliance_results": audit_data.get("compliance_results",[]),
            "final_status": audit_data.get("status","Failed"),
            "final_report": audit_data.get("final_report","No report generated.")
        }
        
    except Exception as e:
        logger.error(f"System Error in Auditor Node: {str(e)}")
        
        # logging the raw reponse
        logger.error(f"Raw LLM Response:{response.content if 'response' in locals() else 'No response received'}")
        
        return{
            "error": [str(e)],
            "final_status":"FAIL", 
            "final_report":"An error occurred during compliance checking. Please check the logs for details."
        }
            