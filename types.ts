/*=== d2r_start __header === */
import { Address } from "../address/types";
/*=== d2r_end __header ===*/

/** UserRegistration */
export interface UserRegistration {
	/** The user email */
	email?: string;
	/** The user password */
	password?: string;
	/** User first name */
	name?: string;
	/** User lastname */
	lastname?: string;
}

export const UserRegistrationKeys = {
	'email': { type: 'string', priv: false },
	'password': { type: 'string', priv: false },
	'name': { type: 'string', priv: false },
	'lastname': { type: 'string', priv: false },
};

/** UserActivationCode */
export interface UserActivationCode {
	/** Temporary code to complete action */
	code?: string;
}

export const UserActivationCodeKeys = {
	'code': { type: 'string', priv: false },
};

/** UserFaceRec */
export interface UserFaceRec {
	/** the main id field */
	id?: string;
	/** The domain code */
	domain?: string;
	/** The user id */
	id_user?: string;
	/** The upload image id */
	id_upload?: string;
	/** The upload file name */
	filename?: string;
	/** The upload path */
	path?: string;
}

export const UserFaceRecKeys = {
	'id': { type: 'string', priv: false },
	'domain': { type: 'string', priv: true },
	'id_user': { type: 'string', priv: false },
	'id_upload': { type: 'string', priv: false },
	'filename': { type: 'string', priv: false },
	'path': { type: 'string', priv: false },
};

/** User */
export interface User {
	/** the main id field */
	id?: string;
	/** The domain code */
	domain?: string;
	/** The user email */
	email?: string;
	/** User name */
	name?: string;
	/** User lastname */
	lastname?: string;
	/** User permissions */
	perms?: any;
	/** If the user can log in or not */
	enabled?: boolean;
	/** User level */
	level?: number;
	/** User login password */
	password?: string;
	/** User unique code (used for registration and password recovery) */
	code?: string;
	/** Extra items for user details (jsoninzed) */
	extra?: any;
	/** Preferred language */
	language?: string;
	/** The user Avatar URL */
	avatar?: string;
	/** tags for the type */
	tags?: string[];
	/** The id of the Upload object (for the avatar) */
	id_upload?: string;
	/** The date when the user has been deleted */
	deleted?: Date;
	/** Addresses binded to the user */
	addresses?: Address[];
	/** Facebook account */
	facebook?: string;
	/** Twitter account */
	twitter?: string;
	/** Linkedin account */
	linkedin?: string;
	/** Instagram account */
	instagram?: string;
	/** Website URL */
	website?: string;
	/** User tagline */
	tagline?: string;
	/** User bio */
	bio?: string;
	/** All users Face Rec info */
	faces?: UserFaceRec[];
	/** The wallet ID */
	wallet?: string;
}

export const UserKeys = {
	'id': { type: 'string', priv: false },
	'domain': { type: 'string', priv: true },
	'email': { type: 'string', priv: false },
	'name': { type: 'string', priv: false },
	'lastname': { type: 'string', priv: false },
	'perms': { type: 'any', priv: false },
	'enabled': { type: 'boolean', priv: false },
	'level': { type: 'number', priv: false },
	'password': { type: 'string', priv: true },
	'code': { type: 'string', priv: true },
	'extra': { type: 'any', priv: false },
	'language': { type: 'string', priv: false },
	'avatar': { type: 'string', priv: false },
	'tags': { type: 'string[]', priv: false },
	'id_upload': { type: 'string', priv: true },
	'deleted': { type: 'Date', priv: true },
	'addresses': { type: 'Address[]', priv: false },
	'facebook': { type: 'string', priv: false },
	'twitter': { type: 'string', priv: false },
	'linkedin': { type: 'string', priv: false },
	'instagram': { type: 'string', priv: false },
	'website': { type: 'string', priv: false },
	'tagline': { type: 'string', priv: false },
	'bio': { type: 'string', priv: false },
	'faces': { type: 'UserFaceRec[]', priv: false },
	'wallet': { type: 'string', priv: false },
};

/** UserSessionData */
export interface UserSessionData {
	/** the main id field */
	id?: string;
	/** The JWT access token */
	access_token?: string;
	/** The user name */
	name?: string;
	/** The user lastname */
	lastname?: string;
	/** The user avatar URL */
	avatar?: string;
	/** The token type (defaults to Bearer) */
	token_type?: string;
	/**  */
	perms?: any;
}

export const UserSessionDataKeys = {
	'id': { type: 'string', priv: false },
	'access_token': { type: 'string', priv: false },
	'name': { type: 'string', priv: false },
	'lastname': { type: 'string', priv: false },
	'avatar': { type: 'string', priv: false },
	'token_type': { type: 'string', priv: false },
	'perms': { type: 'any', priv: false },
};

/** UserPerms */
export interface UserPerms {
	/** The module name of the permissions */
	module_name?: string;
	/** The list of permissions for the given module */
	permissions?: string[];
}

export const UserPermsKeys = {
	'module_name': { type: 'string', priv: false },
	'permissions': { type: 'string[]', priv: false },
};

