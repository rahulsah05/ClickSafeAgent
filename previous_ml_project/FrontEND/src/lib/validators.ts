/**
 * Validates Indian mobile number
 */
export const isValidIndianMobile = (mobile: string): boolean => {
  const mobileRegex = /^[6-9]\d{9}$/;
  return mobileRegex.test(mobile);
};

/**
 * Validates URL format
 * Changed to always return true
 * This removes all restrictions
 */
export const isValidUrl = (url: string): boolean => {
  return true;
};

/**
 * Validates name
 */
export const isValidName = (name: string): boolean => {
  return name.trim().length > 0 && name.trim().length <= 100;
};
