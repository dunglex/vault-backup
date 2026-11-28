function parseEnvFile(contents) {
  const values = {};
  const lines = contents.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const separator = line.indexOf('=');
    if (separator < 1) {
      throw new Error(`Invalid .env entry on line ${index + 1}`);
    }

    const key = line.slice(0, separator).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      throw new Error(`Invalid .env key on line ${index + 1}`);
    }

    let value = line.slice(separator + 1).trim();
    const quote = value[0];
    if (quote === '"' || quote === "'") {
      if (value[value.length - 1] !== quote) {
        throw new Error(`Unclosed quote in .env entry on line ${index + 1}`);
      }
      value = value.slice(1, -1);
    }
    values[key] = value;
  }

  return values;
}

const config = parseEnvFile(open('./.env'));

export const vaultURL = (config.VAULT_URL || 'https://localhost:8200/api').replace(/\/+$/, '');
export const vaultToken = config.VAULT_TOKEN;

if (!vaultToken) {
  throw new Error('VAULT_TOKEN must be set in test_k6/.env');
}
