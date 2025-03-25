// a new user has been created in the system  (user)
export const USER_EVENT_CREATE = 'user.create';

// a user has been updated  (mode, user)
export const USER_EVENT_UPDATE = 'user.update';

// a user has been removed (user)
export const USER_EVENT_DELETE = 'user.delete';

// a user has enabled 2FA (user)
export const USER_EVENT_2FA = 'user.2fa';

// a user has changed the domain (user)
export const USER_EVENT_DOMAIN = 'user.domain';

// an user logged in (user)
export const USER_EVENT_LOGIN = 'user.login';

// an user logged out (user)
export const USER_EVENT_LOGOUT = 'user.logout';

// an user tried to login (user)
export const USER_EVENT_LOGIN_TRY = 'user.login_error';