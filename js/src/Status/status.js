// Copyright 2015-2017 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

import React from 'react';
import PropTypes from 'prop-types';
import { observer } from 'mobx-react';
import { FormattedMessage } from 'react-intl';

import BlockNumber from '@parity/ui/lib/BlockNumber';
import ClientVersion from '@parity/ui/lib/ClientVersion';
import GradientBg from '@parity/ui/lib/GradientBg';
import { HomeIcon } from '@parity/ui/lib/Icons';
import IdentityIcon from '@parity/ui/lib/IdentityIcon';
import NetChain from '@parity/ui/lib/NetChain';
import NetPeers from '@parity/ui/lib/NetPeers';
import SignerPending from '@parity/ui/lib/SignerPending';
import StatusIndicator from '@parity/ui/lib/StatusIndicator';

import Consensus from './Consensus';
import AccountStore from '../ParityBar/accountStore';
import ParityBarStore from '../ParityBar/store';
import SyncWarning from '../SyncWarning';
import PluginStore from './pluginStore';
import Upgrade from './Upgrade';

import styles from './status.css';

const pluginStore = PluginStore.get();
const parityBarStore = ParityBarStore.get();

function Status ({ className = '', upgradeStore }, { api }) {
  const accountStore = AccountStore.get(api);

  return (
    <div className={ `${styles.container} ${className}` }>
      <GradientBg className={ styles.fixed }>
        <div className={ styles.status }>
          <a href='#/' className={ styles.home }>
            <HomeIcon />
          </a>
          <ClientVersion className={ styles.version } />
          <div className={ styles.upgrade }>
            <Consensus upgradeStore={ upgradeStore } />
            <Upgrade upgradeStore={ upgradeStore } />
          </div>
          <div className={ styles.plugins }>
            {
              pluginStore.components.map((Component, index) => (
                <Component key={ index } />
              ))
            }
            <div className={ styles.divider } />
            <SignerPending
              className={ styles.signerPending }
              onClick={ parityBarStore.toggleOpenSigner }
            />
            <IdentityIcon
              address={ accountStore.defaultAccount }
              button
              center
              className={ styles.defaultAccount }
              onClick={ parityBarStore.toggleOpenAccounts }
            />
            <StatusIndicator
              className={ styles.health }
              id='application.status.health'
            />
            <div className={ styles.divider } />
            <BlockNumber
              className={ styles.blockNumber }
              message={
                <FormattedMessage
                  id='ui.blockStatus.bestBlock'
                  defaultMessage=' best block'
                />
              }
            />
            <NetPeers
              className={ styles.peers }
              message={
                <FormattedMessage
                  id='ui.netPeers.peers'
                  defaultMessage=' peers'
                />
              }
            />
            <NetChain className={ styles.chain } />
          </div>
        </div>
        <SyncWarning className={ styles.warning } />
      </GradientBg>
    </div>
  );
}

Status.contextTypes = {
  api: PropTypes.object.isRequired
};

Status.propTypes = {
  className: PropTypes.string,
  upgradeStore: PropTypes.object.isRequired
};

export default observer(Status);
