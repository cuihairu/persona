import type { DetectedField } from '../formScanner.js';

export interface SuggestionItem {
    item_id: string;
    title: string;
    username_hint?: string;
    match_strength: number;
    credential_type?: string;
}

export interface FillCredential {
    username?: string;
    password?: string;
    /** Present for BankCard fills; CVV never appears (bridge copy-only). */
    card?: CardFillData;
}

export interface CardFillData {
    card_number: string;
    cardholder_name: string;
    expiry_date: string;
}

// Current page state
export interface PasskeyCandidate {
    id: string;
    rp_id: string;
    user_name?: string;
    user_display_name?: string;
    identity_name?: string;
    created_at: number;
}

export interface PasskeyBridgeReply {
    success: boolean;
    data?: any;
    error?: string;
}

