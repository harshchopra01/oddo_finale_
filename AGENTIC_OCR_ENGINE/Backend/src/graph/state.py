import operator
from typing import Annotated,List,Dict,Optional,Any,TypedDict


# define the schema for a complience result
# issue

class ComplianceIssue(TypedDict):
    category: str     # eg: FTC,
    description: str  # specific details about the issue
    severity: str    # critical, high, medium, low
    timestamp: Optional[str]  # when the issue was detected
    
    
# Define the global graph state : defines the state that passes around the graph during execution, and also defines the final output of the graph execution
class VideoAuditState(TypedDict):
    """define the data schema for langgraph execution state
    Main container : holds all the information about the audit right from initial URL to final report"""
    
    # input-url
    video_url:str
    video_id:str
    
    # ingestion and extraction data
    local_file_path: Optional[str]
    video_metadata: Dict[str,Any]  # {"duration":15,"resolution":"1080p", "format":"mp4"}
    transcript:Optional[str]
    ocr_text:List[str]
    
    
    # output data and store all the voilance that are occured during the audit
    Compliance_results: Annotated[List[ComplianceIssue],operator.add]
    
    # final delivery
    final_status: str # PASS/FAIL
    
    final_report: str # markdown formate
    
    
    # system observability
    # errors : API timeout
    errors : Annotated[List[str],operator.add]