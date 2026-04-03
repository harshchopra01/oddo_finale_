'''
This module defines the DAG : Directed Acyclic Graph that archestrates the video auditing process.
It defines the nodes and edges of the graph, 
and the execution logic for each node.

it connects the nodes using the stategraph from langGraph

START-> INDEX_VIDEO_NODE -> audit_content_node -> END
'''

from langgraph.graph import StateGraph,START,END
from backend.src.graph.state import VideoAuditState

from backend.src.graph.node import (
    index_video_node,
    audit_content_node
)

def create_graph():
    '''
    Construct and compiles the langgraph workflow return:
    compiled graph : runnnable graph object for execution'''

    # Create a new state graph
    
    workflow = StateGraph(VideoAuditState)
    
    # add nodes to the graph
    
    workflow.add_node("indexer",index_video_node)
    workflow.add_node("auditor",audit_content_node)
    
    # define the entry point
    workflow.set_entry_point("indexer")
    
    # define the edges
    
    workflow.add_edge("indexer","auditor")
    
    # once the audit of the content is done, we can end the workflow
    workflow.add_edge("auditor",END)
    
    compile_workflow = workflow.compile()
    return compile_workflow


# expose this runnable app

app = create_graph()
    