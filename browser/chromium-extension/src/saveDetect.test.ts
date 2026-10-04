import {
    classifySaveScenario,
    extractSaveProposal,
    type SaveScanInput
} from './saveDetect';

function input(overrides: Partial<SaveScanInput>): SaveScanInput {
    return {
        inputType: 'text',
        autocomplete: '',
        name: '',
        id: '',
        placeholder: '',
        ariaLabel: '',
        value: '',
        ...overrides
    };
}

describe('classifySaveScenario', () => {
    it('classifies a single plain password field as login', () => {
        const inputs = [
            input({ inputType: 'text', name: 'login', value: 'bob' }),
            input({ inputType: 'password', name: 'pass', value: 'pw' })
        ];
        expect(classifySaveScenario(inputs)).toBe('login');
    });

    it('classifies autocomplete=new-password as new', () => {
        const inputs = [
            input({ inputType: 'email', name: 'email', value: 'b@e.com' }),
            input({ inputType: 'password', name: 'pass', value: 'pw', autocomplete: 'new-password' })
        ];
        expect(classifySaveScenario(inputs)).toBe('new');
    });

    it('classifies two password fields without current as new (password+confirm)', () => {
        const inputs = [
            input({ inputType: 'text', name: 'user', value: 'bob' }),
            input({ inputType: 'password', name: 'pass', value: 'pw' }),
            input({ inputType: 'password', name: 'confirm', value: 'pw' })
        ];
        expect(classifySaveScenario(inputs)).toBe('new');
    });

    it('classifies current-password + new-password as change', () => {
        const inputs = [
            input({ inputType: 'password', name: 'old', value: 'old', autocomplete: 'current-password' }),
            input({ inputType: 'password', name: 'new', value: 'new' })
        ];
        expect(classifySaveScenario(inputs)).toBe('change');
    });

    it('classifies a form without password fields as login', () => {
        const inputs = [input({ inputType: 'text', name: 'q', value: 'x' })];
        expect(classifySaveScenario(inputs)).toBe('login');
    });
});

describe('extractSaveProposal', () => {
    it('returns null when no password field is filled', () => {
        const inputs = [
            input({ inputType: 'text', name: 'user', value: 'bob' }),
            input({ inputType: 'password', name: 'pass' })
        ];
        expect(extractSaveProposal(inputs)).toBeNull();
    });

    it('picks the email field as username', () => {
        const inputs = [
            input({ inputType: 'email', name: 'email', value: 'bob@example.com' }),
            input({ inputType: 'password', name: 'pass', value: 'pw' })
        ];
        const proposal = extractSaveProposal(inputs, 'Example', 'example.com');
        expect(proposal?.username).toBe('bob@example.com');
        expect(proposal?.password).toBe('pw');
        expect(proposal?.scenario).toBe('login');
    });

    it('picks a text field with a username-ish name as username', () => {
        const inputs = [
            input({ inputType: 'text', name: 'account_identifier', value: 'bob42' }),
            input({ inputType: 'password', name: 'pass', value: 'pw' })
        ];
        expect(extractSaveProposal(inputs)?.username).toBe('bob42');
    });

    it('returns undefined username when no field looks like one', () => {
        const inputs = [
            input({ inputType: 'text', name: 'search', value: 'shoes' }),
            input({ inputType: 'password', name: 'pass', value: 'pw' })
        ];
        expect(extractSaveProposal(inputs)?.username).toBeUndefined();
    });

    it('stores the last password for change forms (current → new order)', () => {
        const inputs = [
            input({ inputType: 'password', name: 'old', value: 'current-pw', autocomplete: 'current-password' }),
            input({ inputType: 'password', name: 'new', value: 'brand-new-pw' })
        ];
        const proposal = extractSaveProposal(inputs);
        expect(proposal?.scenario).toBe('change');
        expect(proposal?.password).toBe('brand-new-pw');
    });

    it('stores the first password for registration (password+confirm equal)', () => {
        const inputs = [
            input({ inputType: 'email', name: 'email', value: 'b@e.com' }),
            input({ inputType: 'password', name: 'pass', value: 'reg-pw', autocomplete: 'new-password' }),
            input({ inputType: 'password', name: 'confirm', value: 'reg-pw' })
        ];
        const proposal = extractSaveProposal(inputs);
        expect(proposal?.scenario).toBe('new');
        expect(proposal?.password).toBe('reg-pw');
    });

    it('prefers the document title as name hint, falling back to host', () => {
        const inputs = [input({ inputType: 'password', name: 'pass', value: 'pw' })];
        expect(extractSaveProposal(inputs, 'Example — Sign In', 'example.com')?.nameHint).toBe(
            'Example — Sign In'
        );
        expect(extractSaveProposal(inputs, '   ', 'example.com')?.nameHint).toBe('example.com');
        expect(extractSaveProposal(inputs)?.nameHint).toBeUndefined();
    });
});
