export interface SelectOption {
  value: string;
  label: string;
}

export interface SelectFieldProps {
  id: string;
  label: string;
  value: string;
  options: readonly SelectOption[];
  onChange: (value: string) => void;
  disabled?: boolean;
  className?: string;
}

export function SelectField({ id, label, value, options, onChange, disabled, className = "" }: SelectFieldProps) {
  return (
    <div className={className}>
      <label htmlFor={id} className="label">
        {label}
      </label>
      <select
        id={id}
        className="input pr-8"
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}
