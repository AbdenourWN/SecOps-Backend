import httpx
import json

class AIService:
    def __init__(self):
        # The default URL for Ollama
        self.ollama_url = "http://localhost:11434/api/generate"
        
        # We use 'llama3' since you installed it. 
        # You can change this to 'mistral' easily.
        self.model = "llama3:latest" 

    async def analyze_incident(self, incident_description: str, logs: list[str]) -> str:
        """
        Sends the incident context to the local AI and asks for a summary.
        """
        
        # 1. Prepare the Evidence (Last 15 logs)
        # We join the list of strings into one big text block
        log_text = "\n".join(logs[-15:]) 
        
        # 2. Construct the Prompt (The "Intelligence")
        prompt = f"""
        You are a Senior Security Operations Center (SOC) Analyst.
        
        TASK: Analyze the following security incident and provide a structured report.
        
        --- INCIDENT DETAILS ---
        Description: {incident_description}
        
        --- LOG EVIDENCE ---
        {log_text}
        
        --- REQUIRED OUTPUT FORMAT ---
        Please provide a response in Markdown format with these sections:
        
        ### 1. Analysis
        (Explain what is happening in simple terms. Is this a real attack or a false positive?)
        
        ### 2. Severity Assessment
        (Low / Medium / High / Critical - and why?)
        
        ### 3. Recommended Remediation
        (Give specific Linux commands to fix this or investigate further.)
        """

        # 3. Payload for Ollama
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False # We want the whole answer at once, not word-by-word
        }

        print(f"🧠 AI is thinking about: {incident_description}...")

        try:
            # We use a long timeout (60s) because Llama3 might take time to think
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(self.ollama_url, json=payload)
                
                if response.status_code != 200:
                    return f"Error: Ollama returned status {response.status_code}"
                
                result = response.json()
                # The actual text reply is in the 'response' key
                return result.get("response", "No response from AI.")
                
        except Exception as e:
            error_msg = f"❌ Connection Error: {str(e)}"
            print(error_msg)
            # RETURN THE ACTUAL ERROR so we can see it in Postman
            return error_msg