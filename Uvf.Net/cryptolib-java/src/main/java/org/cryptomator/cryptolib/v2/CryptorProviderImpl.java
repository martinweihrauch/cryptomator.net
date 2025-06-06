/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;

import java.security.SecureRandom;

public class CryptorProviderImpl implements CryptorProvider {

	@Override
	public Scheme scheme() {
		return Scheme.SIV_GCM;
	}

	@Override
	public Cryptor provide(Masterkey masterkey, SecureRandom random) {
		if (masterkey instanceof PerpetualMasterkey) {
			PerpetualMasterkey perpetualMasterkey = (PerpetualMasterkey) masterkey;
			return new CryptorImpl(perpetualMasterkey, ReseedingSecureRandom.create(random));
		} else {
			throw new IllegalArgumentException("V2 Cryptor requires a PerpetualMasterkey.");
		}
	}

}
