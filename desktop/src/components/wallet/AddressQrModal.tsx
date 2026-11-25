import React from 'react';
import { useTranslation } from 'react-i18next';
import { QRCodeSVG } from 'qrcode.react';

interface AddressQrModalProps {
  address: string;
  /** Closes when the backdrop is clicked */
  onClose: () => void;
}

/** Receive-address QR modal: copies the address and closes */
const AddressQrModal: React.FC<AddressQrModalProps> = ({ address, onClose }) => {
  const { t } = useTranslation();
  return (
    <div
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="bg-white dark:bg-gray-900 rounded-lg p-6 max-w-sm w-full mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="text-lg font-semibold mb-4">{t('wallet.receiveAddress')}</h3>
        <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg mb-4 flex items-center justify-center">
          <QRCodeSVG
            value={address}
            size={192}
            level="M"
            data-testid="address-qr"
          />
        </div>
        <code className="block text-sm text-center text-gray-600 dark:text-gray-300 mb-4 break-all">
          {address}
        </code>
        <button
          onClick={() => {
            navigator.clipboard.writeText(address);
            onClose();
          }}
          className="w-full px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
        >
          {t('wallet.copyAddress')}
        </button>
      </div>
    </div>
  );
};

export default AddressQrModal;
