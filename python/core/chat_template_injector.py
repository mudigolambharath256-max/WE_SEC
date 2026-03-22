"""
Chat template injector — wraps payloads in model-native templates.

Coordinates with Go's ChatInject implementation but provides Python-side
template management and multi-turn conversation handling.
"""

from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


# Template definitions (matches Go implementation)
TEMPLATES = {
    "qwen": {
        "name": "Qwen",
        "start": "<|im_start|>",
        "end": "<|im_end|>",
        "system_format": "<|im_start|>system\n{content}<|im_end|>\n",
        "user_format": "<|im_start|>user\n{content}<|im_end|>\n",
        "assistant_format": "<|im_start|>assistant\n{content}<|im_end|>\n",
    },
    "chatgpt": {
        "name": "ChatGPT",
        "start": "<|im_start|>",
        "end": "<|im_end|>",
        "system_format": "<|im_start|>system\n{content}<|im_end|>\n",
        "user_format": "<|im_start|>user\n{content}<|im_end|>\n",
        "assistant_format": "<|im_start|>assistant\n{content}<|im_end|>\n",
    },
    "llama3": {
        "name": "Llama3",
        "start": "<|begin_of_text|><|start_header_id|>",
        "end": "<|eot_id|>",
        "system_format": "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n{content}<|eot_id|>",
        "user_format": "<|start_header_id|>user<|end_header_id|>\n\n{content}<|eot_id|>",
        "assistant_format": "<|start_header_id|>assistant<|end_header_id|>\n\n{content}<|eot_id|>",
    },
    "mistral": {
        "name": "Mistral",
        "start": "[INST]",
        "end": "[/INST]",
        "system_format": "[INST] {content} [/INST]\n",
        "user_format": "[INST] {content} [/INST]\n",
        "assistant_format": "{content}\n",
    },
    "gemma": {
        "name": "Gemma",
        "start": "<start_of_turn>",
        "end": "<end_of_turn>",
        "system_format": "<start_of_turn>system\n{content}<end_of_turn>\n",
        "user_format": "<start_of_turn>user\n{content}<end_of_turn>\n",
        "assistant_format": "<start_of_turn>model\n{content}<end_of_turn>\n",
    },
    "phi": {
        "name": "Phi",
        "start": "<|system|>",
        "end": "<|end|>",
        "system_format": "<|system|>\n{content}<|end|>\n",
        "user_format": "<|user|>\n{content}<|end|>\n",
        "assistant_format": "<|assistant|>\n{content}<|end|>\n",
    },
}


class ChatTemplateInjector:
    """
    Manages chat template injection for multi-turn conversations.
    """
    
    def __init__(self, template_id: Optional[str] = None):
        """
        Initialize template injector.
        
        Args:
            template_id: Template identifier (qwen, llama3, etc.)
        """
        self.template_id = template_id
        self.template = TEMPLATES.get(template_id) if template_id else None
        self.conversation_history: List[Dict[str, str]] = []
        
        if self.template:
            logger.info(f"ChatTemplateInjector initialized with template: {template_id}")
        else:
            logger.info("ChatTemplateInjector initialized without template (will use mixture)")
    
    def wrap_message(self, content: str, role: str = "user") -> str:
        """
        Wrap a message in template format.
        
        Args:
            content: Message content
            role: Message role (system, user, assistant)
            
        Returns:
            str: Wrapped message
        """
        if not self.template:
            # No template - return raw content
            return content
        
        format_key = f"{role}_format"
        if format_key not in self.template:
            logger.warning(f"No format for role '{role}' in template {self.template_id}")
            return content
        
        return self.template[format_key].format(content=content)
    
    def build_conversation(
        self,
        messages: List[Dict[str, str]],
        include_history: bool = True
    ) -> str:
        """
        Build a complete conversation from messages.
        
        Args:
            messages: List of {role, content} dicts
            include_history: Include conversation history
            
        Returns:
            str: Complete conversation string
        """
        conversation_parts = []
        
        # Include history if requested
        if include_history and self.conversation_history:
            for msg in self.conversation_history:
                wrapped = self.wrap_message(msg["content"], msg["role"])
                conversation_parts.append(wrapped)
        
        # Add new messages
        for msg in messages:
            wrapped = self.wrap_message(msg["content"], msg["role"])
            conversation_parts.append(wrapped)
        
        return "".join(conversation_parts)
    
    def inject_system_prompt(self, system_prompt: str, user_message: str) -> str:
        """
        Inject a system prompt before user message.
        
        Args:
            system_prompt: System prompt content
            user_message: User message content
            
        Returns:
            str: Complete conversation with system prompt
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]
        
        return self.build_conversation(messages, include_history=False)
    
    def add_to_history(self, role: str, content: str):
        """
        Add a message to conversation history.
        
        Args:
            role: Message role
            content: Message content
        """
        self.conversation_history.append({"role": role, "content": content})
    
    def clear_history(self):
        """Clear conversation history."""
        self.conversation_history = []
        logger.debug("Conversation history cleared")
    
    def get_mixture_prefix(self) -> str:
        """
        Get mixture-of-templates prefix.
        
        Returns:
            str: Concatenated start tokens from all templates
        """
        seen = set()
        prefix_parts = []
        
        for template in TEMPLATES.values():
            start_token = template["start"]
            if start_token not in seen:
                prefix_parts.append(start_token)
                seen.add(start_token)
        
        return "".join(prefix_parts)
    
    def wrap_with_mixture(self, content: str) -> str:
        """
        Wrap content with mixture-of-templates prefix.
        
        Args:
            content: Content to wrap
            
        Returns:
            str: Content with mixture prefix
        """
        prefix = self.get_mixture_prefix()
        return prefix + content
    
    @staticmethod
    def detect_template(response: str) -> Optional[str]:
        """
        Detect template format from response.
        
        Args:
            response: Model response
            
        Returns:
            str: Detected template ID, or None
        """
        for template_id, template in TEMPLATES.items():
            if template["start"] in response or template["end"] in response:
                return template_id
        
        return None
    
    @staticmethod
    def get_available_templates() -> List[str]:
        """
        Get list of available template IDs.
        
        Returns:
            list: Template IDs
        """
        return list(TEMPLATES.keys())
    
    @staticmethod
    def get_template_info(template_id: str) -> Optional[Dict]:
        """
        Get information about a template.
        
        Args:
            template_id: Template identifier
            
        Returns:
            dict: Template information, or None
        """
        return TEMPLATES.get(template_id)


def create_multi_turn_attack(
    template_id: str,
    turns: List[Dict[str, str]]
) -> str:
    """
    Create a multi-turn attack conversation.
    
    Args:
        template_id: Template identifier
        turns: List of {role, content} dicts for each turn
        
    Returns:
        str: Complete multi-turn conversation
    """
    injector = ChatTemplateInjector(template_id)
    return injector.build_conversation(turns, include_history=False)


def inject_jailbreak_prefix(
    template_id: str,
    jailbreak_prompt: str,
    target_prompt: str
) -> str:
    """
    Inject jailbreak prompt before target prompt.
    
    Args:
        template_id: Template identifier
        jailbreak_prompt: Jailbreak/system prompt
        target_prompt: Target user prompt
        
    Returns:
        str: Complete conversation with jailbreak
    """
    injector = ChatTemplateInjector(template_id)
    return injector.inject_system_prompt(jailbreak_prompt, target_prompt)
