"""Regression tests for the temporary pre-refactor import paths."""


def test_legacy_llm_exports_match_modular_api():
    from pentron.ai.analysis import AnalysisIncompleteError, analyse_target
    from pentron.ai.models import AnalysisResult
    from pentron.llm import (
        AnalysisIncompleteError as LegacyAnalysisIncompleteError,
    )
    from pentron.llm import AnalysisResult as LegacyAnalysisResult
    from pentron.llm import analyse_target as legacy_analyse_target

    assert legacy_analyse_target is analyse_target
    assert LegacyAnalysisIncompleteError is AnalysisIncompleteError
    assert LegacyAnalysisResult is AnalysisResult


def test_legacy_chat_exports_match_modular_api():
    from pentron.ai.chat import ChatProviderError, send_chat_message
    from pentron.chat import ChatProviderError as LegacyChatProviderError
    from pentron.chat import send_chat_message as legacy_send_chat_message

    assert legacy_send_chat_message is send_chat_message
    assert LegacyChatProviderError is ChatProviderError


def test_legacy_provider_exports_match_modular_api():
    from pentron.ai.providers import ProviderResponse, get_provider
    from pentron.providers import ProviderResponse as LegacyProviderResponse
    from pentron.providers import get_provider as legacy_get_provider

    assert legacy_get_provider is get_provider
    assert LegacyProviderResponse is ProviderResponse
