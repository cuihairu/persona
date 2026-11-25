/** Glyph and colors for the network badge; a pure function so cards and future lists can reuse it */
export const getNetworkIcon = (network: string): string => {
  switch (network.toLowerCase()) {
    case 'bitcoin':
    case 'btc':
      return '₿';
    case 'ethereum':
    case 'eth':
      return 'Ξ';
    case 'solana':
    case 'sol':
      return '◎';
    default:
      return '💰';
  }
};

export const getNetworkColor = (network: string): string => {
  switch (network.toLowerCase()) {
    case 'bitcoin':
    case 'btc':
      return 'text-orange-600 dark:text-orange-400 bg-orange-100 dark:bg-orange-500/10';
    case 'ethereum':
    case 'eth':
      return 'text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-500/10';
    case 'solana':
    case 'sol':
      return 'text-purple-600 dark:text-purple-400 bg-purple-100 dark:bg-purple-500/10';
    default:
      return 'text-gray-600 dark:text-gray-300 bg-gray-100 dark:bg-gray-800';
  }
};
