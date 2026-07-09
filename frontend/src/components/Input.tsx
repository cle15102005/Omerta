import React, { useState } from 'react';
import { Eye, EyeOff, Copy } from 'lucide-react';
import toast from 'react-hot-toast';
import zxcvbn from 'zxcvbn';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, className = '', ...props }, ref) => {
    return (
      <div className={`flex-col flex gap-2 ${className}`}>
        {label && <label className="text-sm text-accent">{label}</label>}
        <input ref={ref} autoComplete="off" spellCheck="false" data-form-type="other" {...props} />
        {error && <span className="text-danger text-sm">{error}</span>}
      </div>
    );
  }
);
Input.displayName = 'Input';

interface PasswordInputProps extends InputProps {
  showStrength?: boolean;
}

export const PasswordInput = React.forwardRef<HTMLInputElement, PasswordInputProps>(
  ({ showStrength, value, onChange, className = '', ...props }, ref) => {
    const [show, setShow] = useState(false);

    const valStr = typeof value === 'string' ? value : '';
    const score = showStrength && valStr ? zxcvbn(valStr).score : 0;
    const strengthColors = ['var(--danger)', '#ff8c00', '#ffd700', 'var(--accent)', 'var(--accent-alt)'];
    const strengthLabels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    const strengthColor = strengthColors[score];
    const strengthLabel = strengthLabels[score];

    const copyToClipboard = () => {
      if (valStr) {
        navigator.clipboard.writeText(valStr);
        toast.success('Copied to clipboard', { style: { background: 'var(--surface)', color: 'var(--text)', border: '1px solid var(--accent)' } });
      }
    };

    return (
      <div className={`flex-col flex gap-2 ${className}`}>
        {props.label && <label className="text-sm text-accent">{props.label}</label>}
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
          <input
            ref={ref}
            type={show ? 'text' : 'password'}
            value={value}
            onChange={onChange}
            autoComplete="new-password"
            data-form-type="other"
            style={{ paddingRight: '70px' }}
            {...props}
          />
          <div style={{ position: 'absolute', right: '10px', display: 'flex', gap: '8px' }}>
            <button
              type="button"
              className="btn-ghost"
              style={{ padding: '4px', border: 'none' }}
              onClick={() => setShow(!show)}
            >
              {show ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
            <button
              type="button"
              className="btn-ghost"
              style={{ padding: '4px', border: 'none' }}
              onClick={copyToClipboard}
              title="Copy"
            >
              <Copy size={16} />
            </button>
          </div>
        </div>
        {props.error && <span className="text-danger text-sm">{props.error}</span>}
        {showStrength && valStr.length > 0 && (
          <div className="flex flex-col gap-1 mt-1">
            <div style={{ display: 'flex', gap: '4px' }}>
              {[0, 1, 2, 3].map((i) => (
                <div
                  key={i}
                  style={{
                    height: '4px',
                    flex: 1,
                    background: i <= (score === 4 ? 3 : score) ? strengthColor : 'var(--text-dim)',
                    borderRadius: '2px',
                    boxShadow: i <= (score === 4 ? 3 : score) ? `0 0 5px ${strengthColor}` : 'none',
                  }}
                />
              ))}
            </div>
            <div style={{ fontSize: '0.75rem', color: strengthColor, textAlign: 'right', fontWeight: 'bold' }}>
              {strengthLabel}
            </div>
          </div>
        )}
      </div>
    );
  }
);
PasswordInput.displayName = 'PasswordInput';
