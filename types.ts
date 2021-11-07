/*=== d2r_start __header === */
import { Address } from "../address/types";
/*=== d2r_end __header ===*/

/** UserRegistration */
export interface UserRegistration {
	/** The user email */
	email?: string;
	/** The user password */
	password?: string;
	/** The user first name */
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
	/** The Face Rec ID */
	id?: string;
	/** The Domain code */
	domain?: string;
	/** The user ID */
	id_user?: string;
	/** The Upload File id */
	id_upload?: string;
	/** The Upload File filename */
	filename?: string;
	/** The Upload file path */
	path?: string;
}

export const UserFaceRecKeys = {
	'id': { type: 'string', priv: false },
	'domain': { type: 'string', priv: false },
	'id_user': { type: 'string', priv: false },
	'id_upload': { type: 'string', priv: false },
	'filename': { type: 'string', priv: false },
	'path': { type: 'string', priv: false },
};

/** User */
export interface User {
	/** The user id */
	id?: string;
	/** The domain name */
	domain?: string;
	/** The user email */
	email?: string;
	/** The user first name */
	name?: string;
	/** The user last name */
	lastname?: string;
	/** All user permissions */
	perms?: any;
	/** Flag T/F to know if the user is enabled */
	enabled?: boolean;
	/** The user level */
	level?: number;
	/** The encrypted user password */
	password?: string;
	/** User unique code (used for registration and password recovery) */
	code?: string;
	/** Extra items for user details (jsoninzed) */
	extra?: any;
	/** Preferred language */
	language?: string;
	/** Tags added to the user */
	tags?: string[];
	/** The user avatar URL */
	avatar?: string;
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
	/** Website personal */
	website?: string;
	/** User tagline */
	tagline?: string;
	/** User bio */
	bio?: string;
	/** All users Face Rec info */
	faces?: UserFaceRec[];
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
	'tags': { type: 'string[]', priv: false },
	'avatar': { type: 'string', priv: false },
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
};

/** UserSessionData */
export interface UserSessionData {
	/** The user id */
	id?: string;
	/** The JWT access token */
	access_token?: string;
	/** The token type (defaults to Bearer) */
	token_type?: string;
	/** The user name */
	name?: string;
	/** The user lastname */
	lastname?: string;
	/** The user avatar URL */
	avatar?: string;
}

export const UserSessionDataKeys = {
	'id': { type: 'string', priv: false },
	'access_token': { type: 'string', priv: false },
	'token_type': { type: 'string', priv: false },
	'name': { type: 'string', priv: false },
	'lastname': { type: 'string', priv: false },
	'avatar': { type: 'string', priv: false },
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

