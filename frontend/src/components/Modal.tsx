import React from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: React.ReactNode;
  children: React.ReactNode;
  hideClose?: boolean;
}

export function Modal({ isOpen, onClose, title, children, hideClose = false }: ModalProps) {
  if (!isOpen) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0, left: 0, right: 0, bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.7)',
        backdropFilter: 'blur(5px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 50, // ensures it's above the CRT scanlines
      }}
    >
      <div className="card animate-fade-in" style={{ width: '90%', maxWidth: '500px', maxHeight: '90vh', overflowY: 'auto' }}>
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-accent">{title}</h2>
          {!hideClose && (
            <button className="btn-ghost" onClick={onClose} style={{ padding: '4px' }}>
              <X size={20} />
            </button>
          )}
        </div>
        <div>
          {children}
        </div>
      </div>
    </div>
  );
}
