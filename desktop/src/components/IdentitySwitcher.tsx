import React, { useState } from 'react';
import {
  UserCircleIcon,
  PlusIcon,
  ChevronDownIcon,
  BriefcaseIcon,
  HomeIcon,
  UserGroupIcon,
  CreditCardIcon,
  PuzzlePieceIcon
} from '@heroicons/react/24/outline';
import { Listbox, Transition } from '@headlessui/react';
import { usePersonaService } from '@/hooks/usePersonaService';
import type { IdentityType } from '@/types';
import { clsx } from 'clsx';

const getIdentityIcon = (type: string) => {
  switch (type) {
    case 'Personal':
      return HomeIcon;
    case 'Work':
      return BriefcaseIcon;
    case 'Social':
      return UserGroupIcon;
    case 'Financial':
      return CreditCardIcon;
    case 'Gaming':
      return PuzzlePieceIcon;
    default:
      return UserCircleIcon;
  }
};

const getIdentityColor = (type: string) => {
  switch (type) {
    case 'Personal':
      return 'bg-blue-100 text-blue-800';
    case 'Work':
      return 'bg-purple-100 text-purple-800';
    case 'Social':
      return 'bg-green-100 text-green-800';
    case 'Financial':
      return 'bg-red-100 text-red-800';
    case 'Gaming':
      return 'bg-yellow-100 text-yellow-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
};

interface IdentitySwitcherProps {
  onCreateIdentity: () => void;
}

const IdentitySwitcher: React.FC<IdentitySwitcherProps> = ({ onCreateIdentity }) => {
  const { identities, currentIdentity, switchIdentity } = usePersonaService();

  return (
    <div className="relative">
      <Listbox value={currentIdentity} onChange={switchIdentity}>
        <div className="relative">
          <Listbox.Button className="relative w-full cursor-default rounded-lg bg-white py-2 pl-3 pr-10 text-left shadow-md focus:outline-none focus-visible:border-primary-500 focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-opacity-75 focus-visible:ring-offset-2 focus-visible:ring-offset-primary-300 sm:text-sm">
            <div className="flex items-center">
              {currentIdentity ? (
                <>
                  <div className={clsx(
                    'flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center mr-3',
                    getIdentityColor(currentIdentity.identity_type)
                  )}>
                    {React.createElement(getIdentityIcon(currentIdentity.identity_type), {
                      className: 'w-4 h-4'
                    })}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {currentIdentity.name}
                    </p>
                    <p className="text-xs text-gray-500">
                      {currentIdentity.identity_type}
                    </p>
                  </div>
                </>
              ) : (
                <div className="flex items-center">
                  <UserCircleIcon className="w-8 h-8 text-gray-400 mr-3" />
                  <span className="text-gray-500">Select an identity</span>
                </div>
              )}
            </div>
            <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
              <ChevronDownIcon className="h-5 w-5 text-gray-400" aria-hidden="true" />
            </span>
          </Listbox.Button>

          <Transition
            enter="transition duration-100 ease-out"
            enterFrom="transform scale-95 opacity-0"
            enterTo="transform scale-100 opacity-100"
            leave="transition duration-75 ease-out"
            leaveFrom="transform scale-100 opacity-100"
            leaveTo="transform scale-95 opacity-0"
          >
            <Listbox.Options className="absolute z-10 mt-1 w-full bg-white shadow-lg max-h-60 rounded-md py-1 text-base ring-1 ring-black ring-opacity-5 overflow-auto focus:outline-none sm:text-sm">
              {identities.map((identity) => (
                <Listbox.Option
                  key={identity.id}
                  className={({ active }) =>
                    clsx(
                      'relative cursor-default select-none py-2 pl-3 pr-9',
                      active ? 'bg-primary-100 text-primary-900' : 'text-gray-900'
                    )
                  }
                  value={identity}
                >
                  {({ selected }) => (
                    <div className="flex items-center">
                      <div className={clsx(
                        'flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3',
                        getIdentityColor(identity.identity_type)
                      )}>
                        {React.createElement(getIdentityIcon(identity.identity_type), {
                          className: 'w-3 h-3'
                        })}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className={clsx(
                          'text-sm truncate',
                          selected ? 'font-medium' : 'font-normal'
                        )}>
                          {identity.name}
                        </p>
                        <p className="text-xs text-gray-500">
                          {identity.identity_type}
                        </p>
                      </div>
                      {selected && (
                        <span className="absolute inset-y-0 right-0 flex items-center pr-4">
                          <div className="w-2 h-2 bg-primary-600 rounded-full"></div>
                        </span>
                      )}
                    </div>
                  )}
                </Listbox.Option>
              ))}

              <div className="border-t border-gray-200 mt-1 pt-1">
                <button
                  onClick={onCreateIdentity}
                  className="w-full text-left px-3 py-2 text-sm text-primary-600 hover:bg-primary-50 flex items-center"
                >
                  <PlusIcon className="w-4 h-4 mr-2" />
                  Create new identity
                </button>
              </div>
            </Listbox.Options>
          </Transition>
        </div>
      </Listbox>
    </div>
  );
};

interface CreateIdentityModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const CreateIdentityModal: React.FC<CreateIdentityModalProps> = ({ isOpen, onClose }) => {
  const [name, setName] = useState('');
  const [identityType, setIdentityType] = useState<IdentityType>('Personal');
  const [description, setDescription] = useState('');
  const { createIdentity, isLoading } = usePersonaService();

  const identityTypes: IdentityType[] = ['Personal', 'Work', 'Social', 'Financial', 'Gaming'];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    const result = await createIdentity(name, identityType, description || undefined);
    if (result) {
      setName('');
      setDescription('');
      setIdentityType('Personal');
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Create New Identity</h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="identity-name" className="label mb-2 block">
              Identity Name
            </label>
            <input
              id="identity-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="input"
              placeholder="e.g., John Doe, Work Profile"
              required
            />
          </div>

          <div>
            <label htmlFor="identity-type" className="label mb-2 block">
              Type
            </label>
            <select
              id="identity-type"
              value={identityType}
              onChange={(e) => setIdentityType(e.target.value as IdentityType)}
              className="input"
            >
              {identityTypes.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="identity-description" className="label mb-2 block">
              Description (Optional)
            </label>
            <textarea
              id="identity-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="input h-20 resize-none"
              placeholder="Brief description of this identity"
            />
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary flex-1"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading || !name.trim()}
              className="btn-primary flex-1"
            >
              {isLoading ? 'Creating...' : 'Create Identity'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export { IdentitySwitcher, CreateIdentityModal };