import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  isLoading?: boolean;
}

export function Button({ variant = 'secondary', isLoading, children, className = '', ...props }: ButtonProps) {
  let baseClass = '';
  switch (variant) {
    case 'primary': baseClass = 'btn-primary'; break;
    case 'ghost': baseClass = 'btn-ghost'; break;
    case 'danger': baseClass = 'btn-danger'; break;
    default: baseClass = ''; // 'secondary' is just default button style in our CSS
  }

  return (
    <button className={`${baseClass} ${className}`} disabled={isLoading || props.disabled} {...props}>
      {isLoading ? 'Processing...' : children}
    </button>
  );
}
