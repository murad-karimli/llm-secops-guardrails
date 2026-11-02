import os
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from agent.tools import (
    query_employee_db_vulnerable,
    query_employee_db_secure,
    read_kb_article_vulnerable,
    read_kb_article_secure
)
from agent.prompts import VULNERABLE_SYSTEM_PROMPT, HARDENED_SYSTEM_PROMPT

class SecureAgentEngine:
    def __init__(self, model_name: str = "llama3.2", temperature: float = 0.0):
        ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.llm = ChatOllama(
            model=model_name, 
            temperature=temperature,
            base_url=ollama_host
        )

    def execute(self, user_input: str, phase: int = 0) -> dict:
        """
        Executes agent workflow according to active security phase:
        Phase 0: Vulnerable Baseline (Raw prompt + Raw DB/KB tools)
        Phase 1: Model Hardening (XML boundary + Hardened prompt + Raw DB/KB tools)
        Phase 2 & 3: Least-Privilege & Context Sanitization (XML boundary + Hardened prompt + Sanitized tools)
        """
        if phase == 0:
            system_prompt = VULNERABLE_SYSTEM_PROMPT
            tools = [query_employee_db_vulnerable, read_kb_article_vulnerable]
            formatted_input = user_input
        elif phase == 1:
            system_prompt = HARDENED_SYSTEM_PROMPT
            tools = [query_employee_db_vulnerable, read_kb_article_vulnerable]
            formatted_input = f"<user_input>\n{user_input}\n</user_input>"
        else:
            system_prompt = HARDENED_SYSTEM_PROMPT
            tools = [query_employee_db_secure, read_kb_article_secure]
            formatted_input = f"<user_input>\n{user_input}\n</user_input>"

        llm_with_tools = self.llm.bind_tools(tools)
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=formatted_input)
        ]

        response = llm_with_tools.invoke(messages)
        messages.append(response)

        tool_telemetry = []

        if response.tool_calls:
            tool_map = {
                "query_employee_db_secure": query_employee_db_secure,
                "query_employee_db_vulnerable": query_employee_db_vulnerable,
                "read_kb_article_secure": read_kb_article_secure,
                "read_kb_article_vulnerable": read_kb_article_vulnerable
            }
            for tool_call in response.tool_calls:
                selected_tool = tool_map.get(tool_call["name"])
                if selected_tool:
                    tool_output = selected_tool.invoke(tool_call["args"])
                    tool_telemetry.append({
                        "tool": tool_call["name"],
                        "args": tool_call["args"],
                        "raw_output": tool_output
                    })
                    messages.append(ToolMessage(content=tool_output, tool_call_id=tool_call["id"]))

            final_response = self.llm.invoke(messages)
            output_text = final_response.content
        else:
            output_text = response.content

        return {
            "reply": output_text,
            "tool_calls": tool_telemetry
        }