export function generateOtpCode(length = 6): string {
  let value = '';
  for (let i = 0; i < length; i += 1) {
    value += Math.floor(Math.random() * 10).toString();
  }
  return value;
}

export function otpExpiryDate(minutes = 10): Date {
  const date = new Date();
  date.setMinutes(date.getMinutes() + minutes);
  return date;
}
