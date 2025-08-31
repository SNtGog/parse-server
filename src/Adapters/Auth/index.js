import loadAdapter from '../AdapterLoader';
import Parse from 'parse/node';
import AuthAdapter from './AuthAdapter';

const apple = require('./apple');
const digits = require('./twitter');
const facebook = require('./facebook');
import gcenter from './gcenter';
import github from './github';
const google = require('./google');
import gpgames from './gpgames';
import instagram from './instagram';
const janraincapture = require('./janraincapture');
const janrainengage = require('./janrainengage');
const keycloak = require('./keycloak');
const ldap = require('./ldap');
import line from './line';
import linkedin from './linkedin';
const meetup = require('./meetup');
import mfa from './mfa';
import microsoft from './microsoft';
import oauth2 from './oauth2';
const phantauth = require('./phantauth');
import qq from './qq';
import spotify from './spotify';
import twitter from './twitter';
const vkontakte = require('./vkontakte');
import wechat from './wechat';
import weibo from './weibo';

const anonymous = {
  validateAuthData: () => Promise.resolve(),
  validateAppId: () => Promise.resolve(),
};

const providers = {
  apple,
  gcenter,
  gpgames,
  facebook,
  instagram,
  linkedin,
  meetup,
  mfa,
  google,
  github,
  twitter,
  spotify,
  anonymous,
  digits,
  janrainengage,
  janraincapture,
  line,
  vkontakte,
  qq,
  wechat,
  weibo,
  phantauth,
  microsoft,
  keycloak,
  ldap,
};

const authAdapterPolicies = {
  default: true,
  solo: true,
  additional: true,
};

const ADAPTER_KEYS = [
  'validateAuthData',
  'validateAppId',
  'validateSetUp',
  'validateLogin',
  'validateUpdate',
  'challenge',
  'validateOptions',
  'policy',
  'afterFind',
];

function looksLikeAdapter(x) {
  if (!x) return false;
  if (typeof x === 'function' || typeof x === 'string') return true;
  if (x.module || x.class || x.adapter) return true;
  return (
    typeof x.validateAuthData === 'function' ||
    (typeof x.validateSetUp === 'function' &&
      typeof x.validateLogin === 'function' &&
      typeof x.validateUpdate === 'function')
  );
}

function hasAnyAuthMethod(x) {
  return (
    typeof x?.validateAuthData === 'function' ||
    typeof x?.validateSetUp === 'function' ||
    typeof x?.validateLogin === 'function' ||
    typeof x?.validateUpdate === 'function'
  );
}

function cloneDefaultAdapter(defaultAdapter) {
  return defaultAdapter instanceof AuthAdapter ? defaultAdapter : Object.assign({}, defaultAdapter);
}

function stripDefaultNoops(adapter) {
  const defaultAuthAdapter = new AuthAdapter();
  ADAPTER_KEYS.forEach(key => {
    const existing = adapter?.[key];
    if (
      existing &&
      typeof existing === 'function' &&
      existing.toString() === defaultAuthAdapter[key].toString()
    ) {
      adapter[key] = null;
    }
  });
  return adapter;
}

function mergeAdapterMethods(base, override) {
  if (!override) return base;
  ADAPTER_KEYS.forEach(key => {
    if (override[key]) {
      base[key] = override[key];
    }
  });
  return base;
}

function authDataValidator(provider, adapter, appIds, options) {
  return async function (authData, req, user, requestObject) {
    if (appIds && typeof adapter.validateAppId === 'function') {
      await Promise.resolve(adapter.validateAppId(appIds, authData, options, requestObject));
    }
    if (
      adapter.policy &&
      !authAdapterPolicies[adapter.policy] &&
      typeof adapter.policy !== 'function'
    ) {
      throw new Parse.Error(
        Parse.Error.OTHER_CAUSE,
        'AuthAdapter policy is not configured correctly. The value must be either "solo", "additional", "default" or undefined (will be handled as "default")'
      );
    }
    if (typeof adapter.validateAuthData === 'function') {
      return adapter.validateAuthData(authData, options, requestObject);
    }
    if (
      typeof adapter.validateSetUp !== 'function' ||
      typeof adapter.validateLogin !== 'function' ||
      typeof adapter.validateUpdate !== 'function'
    ) {
      throw new Parse.Error(
        Parse.Error.OTHER_CAUSE,
        'Adapter is not configured. Implement either validateAuthData or all of the following: validateSetUp, validateLogin and validateUpdate'
      );
    }

    const isLoggedIn =
      (req.auth.user && user && req.auth.user.id === user.id) || (user && req.auth.isMaster);

    const hasAuthDataConfigured = !!(
      user &&
      user.get('authData') &&
      user.get('authData')[provider]
    );

    if (isLoggedIn) {
      if (hasAuthDataConfigured) {
        return {
          method: 'validateUpdate',
          validator: () => adapter.validateUpdate(authData, options, requestObject),
        };
      }
      return {
        method: 'validateSetUp',
        validator: () => adapter.validateSetUp(authData, options, requestObject),
      };
    }

    if (hasAuthDataConfigured) {
      return {
        method: 'validateLogin',
        validator: () => adapter.validateLogin(authData, options, requestObject),
      };
    }

    return {
      method: 'validateSetUp',
      validator: () => adapter.validateSetUp(authData, options, requestObject),
    };
  };
}

function loadAuthAdapter(provider, authOptions) {
  let defaultAdapter = providers[provider];

  const providerOptions = authOptions[provider];
  const appIds = providerOptions ? providerOptions.appIds : undefined;

  if (
    providerOptions &&
    Object.prototype.hasOwnProperty.call(providerOptions, 'oauth2') &&
    providerOptions['oauth2'] === true
  ) {
    defaultAdapter = oauth2;
  }

  if (!defaultAdapter && !providerOptions) {
    return;
  }

  let baseAdapter = defaultAdapter ? cloneDefaultAdapter(defaultAdapter) : new AuthAdapter();
  baseAdapter = stripDefaultNoops(baseAdapter);

  let resolvedCustom = null;
  try {
    if (looksLikeAdapter(providerOptions)) {
      resolvedCustom = loadAdapter(
        providerOptions,
        undefined,
        providerOptions?.options || providerOptions
      );
    } else {
      resolvedCustom = providerOptions;
    }
  } catch (e) {
    resolvedCustom = null;
  }

  let finalAdapter;
  if (
    resolvedCustom &&
    (resolvedCustom instanceof AuthAdapter || hasAnyAuthMethod(resolvedCustom))
  ) {
    finalAdapter = resolvedCustom;
  } else {
    finalAdapter = mergeAdapterMethods(baseAdapter, resolvedCustom);
  }

  if (finalAdapter && typeof finalAdapter.validateOptions === 'function') {
    finalAdapter.validateOptions(providerOptions);
  }

  return { adapter: finalAdapter, appIds, providerOptions };
}

module.exports = function (authOptions = {}, enableAnonymousUsers = true) {
  let _enableAnonymousUsers = enableAnonymousUsers;
  const setEnableAnonymousUsers = function (enable) {
    _enableAnonymousUsers = enable;
  };

  const getValidatorForProvider = function (provider) {
    if (provider === 'anonymous' && !_enableAnonymousUsers) {
      return { validator: undefined };
    }
    const authAdapter = loadAuthAdapter(provider, authOptions);
    if (!authAdapter) return;
    const { adapter, appIds, providerOptions } = authAdapter;
    return { validator: authDataValidator(provider, adapter, appIds, providerOptions), adapter };
  };

  const runAfterFind = async (req, authData) => {
    if (!authData) return;
    const adapters = Object.keys(authData);
    await Promise.all(
      adapters.map(async provider => {
        const authAdapter = getValidatorForProvider(provider);
        if (!authAdapter) return;
        const { adapter, providerOptions } = authAdapter;
        const afterFind = adapter.afterFind;
        if (afterFind && typeof afterFind === 'function') {
          const requestObject = {
            ip: req.config.ip,
            user: req.auth.user,
            master: req.auth.isMaster,
          };
          const result = afterFind.call(
            adapter,
            authData[provider],
            providerOptions,
            requestObject
          );
          if (result) {
            authData[provider] = result;
          }
        }
      })
    );
  };

  return Object.freeze({
    getValidatorForProvider,
    setEnableAnonymousUsers,
    runAfterFind,
  });
};

module.exports.loadAuthAdapter = loadAuthAdapter;
