window.vaultFormatDateTime = function(value) {
  return window.vaultFormatDateTimeWithOptions(value, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short'
  });
};

window.vaultFormatCompactDateTime = function(value) {
  return window.vaultFormatDateTimeWithOptions(value, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23'
  }, 'iso');
};

window.vaultFormatDateTimeWithOptions = function(value, options, format) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  for (const timeZone of [window.vaultTimezone || 'UTC', 'UTC']) {
    try {
      if (format === 'iso') {
        const parts = new Intl.DateTimeFormat('en-CA', {...options, timeZone})
          .formatToParts(date)
          .reduce((values, part) => {
            if (part.type !== 'literal') values[part.type] = part.value;
            return values;
          }, {});
        return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}`;
      }
      return new Intl.DateTimeFormat(undefined, {...options, timeZone}).format(date);
    } catch (error) {
      if (error.name !== 'RangeError') throw error;
    }
  }
  return date.toISOString();
};
