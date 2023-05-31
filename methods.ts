
import { ILRequest, ILResponse, LCback, ILiweConfig, ILError, ILiWE } from '../../liwe/types';
import { $l } from '../../liwe/locale';

import {
	User, UserActivationCode, UserActivationCodeKeys, UserDetails, UserDetailsKeys,
	UserFaceRec, UserFaceRecKeys, UserKeys, UserPerms, UserPermsKeys,
	UserRegistration, UserRegistrationKeys, UserSessionData, UserSessionDataKeys,
} from './types';

let _liwe: ILiWE = null;

const _ = ( txt: string, vals: any = null, plural = false ) => {
	return $l( txt, vals, plural, "user" );
};

const COLL_USER_FACERECS = "user_facerecs";
const COLL_USERS = "users";

/*=== f2c_start __file_header === */
import { mkid, challenge_check, challenge_create, isValidEmail, jwt_crypt, jwt_decrypt, keys_filter, keys_valid, random_string, recaptcha_check, set_attr, sha512, unique_code } from '../../liwe/utils';
import { tag_obj } from '../tag/methods';
import { add_suspicious_activity } from '../../liwe/defender';
import { send_mail_template } from '../../liwe/mail';
import { server_fullpath, upload_fullpath } from '../../liwe/liwe';

import { SystemDomain } from '../system/types';
import { system_domain_get_by_code, system_domain_get_by_session } from '../system/methods';
import { session_create, session_del, session_get, session_id, session_remove_all } from '../session/methods';
import { upload_add_file_name, upload_del_file, upload_get } from '../upload/methods';
import { Upload } from '../upload/types';
import { address_add, address_user_list } from '../address/methods';
import { Address } from '../address/types';
import { perm_available } from '../../liwe/auth';
import { adb_collection_init, adb_del_one, adb_find_all, adb_find_one, adb_prepare_filters, adb_query_all, adb_query_one, adb_record_add } from '../../liwe/db/arango';
import { error } from '../../liwe/console_colors';

export const username_exists = async ( req: ILRequest, username: string ): Promise<boolean> => {
	const user: User = await adb_find_one( req.db, COLL_USERS, { username } );

	return user ? true : false;
};

export const email_exists = async ( req: ILRequest, email: string ): Promise<boolean> => {
	const user: User = await adb_find_one( req.db, COLL_USERS, { email } );

	return user ? true : false;
};

export const user_get = async ( id?: string, email?: string, wallet?: string, facerec?: boolean, username?: string, phone?: string ): Promise<User> => {
	const user: User = await adb_find_one( _liwe.db, COLL_USERS, { id, email, wallet, username, phone } );

	if ( !user ) return null;

	if ( !user.extra ) user.extra = '{}';

	if ( typeof user.extra === 'string' )
		user.extra = JSON.parse( user.extra );

	if ( facerec )
		user.faces = await user_facerec_get( { db: _liwe.db } as ILRequest, user.id );

	return user;
};

const user_create = ( email: string, password: string, name: string, lastname: string, enabled: boolean, language: string ) => {
	return { id: mkid( 'user' ), email, password: sha512( password ), name, lastname, enabled, language };
};

const _valid_password = ( pwd: string, err: any, cfg: ILiweConfig ) => {
	if ( !cfg.user.password ) return true;

	if ( !cfg.user.password.enforce ) return true;

	if ( pwd.length < cfg.user.password.min_len ) {
		err.message = _( "Password should be at least {{ cfg.user.password.min_len }} chars long", { cfg } );
		return false;
	}

	if ( !cfg.user.password.secure ) return true;

	if ( !pwd.match( /[A-Z]/ ) ) {
		err.message = _( "Password should contain uppercase letters" );
		return false;
	}

	if ( !pwd.match( /[0-9]/ ) ) {
		err.message = _( "Password should contain numbers" );
		return false;
	}

	const special_chars = '^!.,@#<>+£$%&/();-';
	let found = false;

	special_chars.split( "" ).forEach( ( c ) => {
		if ( found ) return;

		if ( pwd.indexOf( c ) != -1 ) found = true;
	} );

	if ( !found ) {
		err.message = _( "Password should contain one or more special chars: {{ special_chars }}", { special_chars } );
		return false;
	}

	return true;
};

export const middleware_init = ( liwe: ILiWE ) => {
	const auth_header = async ( req: ILRequest, res: ILResponse, next: any ) => {
		const tok = req.headers[ req?.cfg?.security?.header ];

		if ( tok ) {
			const _split = ( tok as string ).split( /bearer/i );
			if ( _split.length > 1 ) {
				const _tok = _split[ 1 ].trim();

				try {
					const data: any = await user_session_get( req, _tok );
					const user = { ...data.user };
					req.user = user;
					req.session = data;
				} catch ( e ) {
					req.user = null;
					req.session = null;
				}
			} else {
				req.user = null;
				req.session = null;
			}
		}

		next();
	};

	liwe.app.use( auth_header );
};

const _avatar_upload = async ( req: ILRequest, u: User ) => {
	const up: Upload = await upload_add_file_name( req, 'avatar', 'user', u.id, 'avatars', null, false, null, u.id );

	if ( !up?.id ) return;

	if ( u.id_upload ) await upload_del_file( u.id_upload );

	u.id_upload = up.id;
	u.avatar = up.filename;
};

const _recaptcha_check = async ( req: ILRequest, recaptcha: string, err: any ) => {
	if ( !_liwe.cfg.user.recaptcha.enabled ) return true;

	if ( !recaptcha || recaptcha.length < 5 ) {
		err.message = _( 'Invalid recaptcha' );
		return false;
	}

	const rc: any = await recaptcha_check( recaptcha );

	if ( rc.success == false ) {
		add_suspicious_activity( req, req.res, `RECAPTCHA error` );
		console.error( "RECAPTCHA ERROR: ", rc );

		return false;
	}

	return true;
};

const _addresses_add = async ( req: ILRequest, u: User ) => {
	const addrs: Address[] = await address_user_list( req, u.id );
	u.addresses = addrs;

	return u;
};

const _password_check = ( req: ILRequest, password: string, user: User, err: any, email?: string ) => {
	if ( !email ) email = user.email;

	if ( user.password != sha512( password ) ) {
		console.error( "Wrong password for user: ", email, password );
		add_suspicious_activity( req, req.res, `Wrong password ${ email }` );
		return false;
	}

	return true;
};

const _create_user_session = async ( req: ILRequest, user: User ) => {
	const tok: any = await user_session_create( req, user );

	const resp: UserSessionData = {
		access_token: tok,
		token_type: 'bearer',
		email: user.email,
		name: user.name,
		lastname: user.lastname,
		id: user.id,
		perms: user.perms,
	};

	return resp;
};

const _create_user = async ( req: ILRequest, err: ILError, username: string, email: string, phone: string, name: string, lastname: string, password: string, enabled = false, visible = false ) => {
	const domain = '__system__';
	const sd: SystemDomain = await system_domain_get_by_code( domain );

	if ( !sd ) {
		err.message = _( 'System domain not found' );
		return null;
	}

	if ( !username ) username = email.split( "@" )[ 0 ].replaceAll( ".", "_" );

	if ( await email_exists( req, email ) ) {
		err.message = _( 'Email already registered' );
		return null;
	}

	if ( await username_exists( req, username ) ) {
		err.message = _( 'Username already registered' );
		return null;
	}

	err.message = _( 'Invalid parameters' );

	let code = unique_code( true, null, false ).slice( 0, 6 ).toUpperCase();
	const dct = {
		id: mkid( 'user' ),
		phone,
		username,
		email,
		password: sha512( password ),
		name,
		lastname,
		enabled,
		visible,
		code,
		id_domain: sd.id,
	};

	if ( !isValidEmail( email ) ) {
		err.message = _( 'Invalid email' );
		return null;
	}

	let u = await user_get( undefined, email );
	if ( u ) {
		add_suspicious_activity( req, req.res, 'Using same email for registration' );
		error( "user %s already exists", email );
		return null;
	}

	if ( !_valid_password( password, err, req.cfg ) ) {
		error( "password for user %s not valid: %s", email, password );
		return null;
	}

	await adb_record_add( req.db, COLL_USERS, dct );

	return dct;
};

const _send_validation_code = ( req: ILRequest, user: User ) => {
	send_mail_template( _( `Activation code: ${ user.code }` ), server_fullpath( "../../etc/templates/user/activation-code.html" ),
		{
			code: user.code,
			name: user.name,
			lastname: user.lastname,
			username: user.username,
			site_name: req.cfg.app.name,
			site_base_url: req.cfg.server.public_url,
		}, user.email, req.cfg.smtp.from, null, null );
};
/*=== f2c_end __file_header ===*/

// {{{ post_user_admin_add ( req: ILRequest, email: string, password: string, name?: string, lastname?: string, perms?: string[], enabled?: boolean, language?: string, cback: LCBack = null ): Promise<User>
/**
 *
 * This endpoint creates a valid user in the system, bypassing registration and verification phases.
 *
 * @param email - The user email [req]
 * @param password - The user password [req]
 * @param name - The user first name [opt]
 * @param lastname - The user lastname [opt]
 * @param perms - User permissions [opt]
 * @param enabled - Flag T/F to know if the user is enabled [opt]
 * @param language - The user language [opt]
 *
 * @return user: User
 *
 */
export const post_user_admin_add = ( req: ILRequest, email: string, password: string, name?: string, lastname?: string, perms?: string[], enabled?: boolean, language?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_admin_add ===*/
		email = email.toLowerCase();

		let u: User = await user_get( null, email );
		const err = { message: _( 'User already exists in the system' ) };
		if ( u ) return cback ? cback( err ) : reject( err );

		if ( !_valid_password( password, err, req.cfg ) )
			return cback ? cback( err ) : reject( err );

		u = { id: mkid( 'user' ), email, password: sha512( password ), name, lastname, enabled, language };
		u = await adb_record_add( req.db, COLL_USERS, u, UserKeys );

		return cback ? cback( null, u ) : resolve( u );
		/*=== f2c_end post_user_admin_add ===*/
	} );
};
// }}}

// {{{ patch_user_admin_update ( req: ILRequest, id: string, email?: string, password?: string, name?: string, lastname?: string, enabled?: boolean, level?: number, language?: string, cback: LCBack = null ): Promise<User>
/**
 *
 * @param id - The user id to be changed [req]
 * @param email - the new user email [opt]
 * @param password - the user password [opt]
 * @param name - the user first name [opt]
 * @param lastname - the user lastname [opt]
 * @param enabled - If the user is enabled or not [opt]
 * @param level - The user level [opt]
 * @param language - The user language [opt]
 *
 * @return user: User
 *
 */
export const patch_user_admin_update = ( req: ILRequest, id: string, email?: string, password?: string, name?: string, lastname?: string, enabled?: boolean, level?: number, language?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start patch_user_admin_update ===*/
		let u: User = await user_get( id );
		const err = { message: _( 'User not found' ) };
		if ( !u ) return cback ? cback( err ) : reject( err );

		if ( email && u.email != email ) {
			const nu: User = await user_get( null, email );
			if ( nu ) {
				err.message = _( 'You cannot use this email address' );
				add_suspicious_activity( req, req.res, `Trying to use an already used email: ${ email }` );
				return cback ? cback( err ) : reject( err );
			}

			u.email = email;
		}

		if ( password ) {
			if ( !_valid_password( password, err, req.cfg ) ) {
				console.error( "ERROR: password for user %s not valid: %s", u.email, password );
				return cback ? cback( err ) : reject( err );
			}

			u.password = sha512( password );
		}

		set_attr( u, "name", name );
		set_attr( u, "lastname", lastname );
		set_attr( u, "enabled", enabled );
		set_attr( u, "level", level );
		set_attr( u, "language", language );

		u.email = u.email.toLowerCase();
		u = await adb_record_add( req.db, COLL_USERS, u, UserKeys );

		return cback ? cback( null, u ) : resolve( u );
		/*=== f2c_end patch_user_admin_update ===*/
	} );
};
// }}}

// {{{ delete_user_admin_del ( req: ILRequest, id_user: string, cback: LCBack = null ): Promise<string>
/**
 *
 * Deletes a user from the system
 *
 * @param id_user - The user ID to be deleted [req]
 *
 * @return id_user: string
 *
 */
export const delete_user_admin_del = ( req: ILRequest, id_user: string, cback: LCback = null ): Promise<string> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start delete_user_admin_del ===*/
		const u: User = await user_get( id_user );
		const err = { message: _( 'User not found' ) };

		if ( !u ) return cback ? cback( err ) : reject( err );

		const d = new Date().toISOString().split( "T" )[ 0 ];

		u.email = `${ u.email }-${ d }`;
		u.enabled = false;
		u.deleted = new Date();

		await adb_record_add( req.db, COLL_USERS, u );

		return cback ? cback( null, id_user ) : resolve( id_user );
		/*=== f2c_end delete_user_admin_del ===*/
	} );
};
// }}}

// {{{ patch_user_admin_fields ( req: ILRequest, id: string, data: any, cback: LCBack = null ): Promise<User>
/**
 *
 * The call modifies a single field.
 * This function returns the full `User` structure
 *
 * @param id - the user id [req]
 * @param data - The field / value to patch [req]
 *
 * @return user: User
 *
 */
export const patch_user_admin_fields = ( req: ILRequest, id: string, data: any, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start patch_user_admin_fields ===*/
		let u: User = await user_get( id );
		const err = { message: _( 'User not found' ) };

		if ( !u ) return cback ? cback( err ) : reject( err );

		u = await adb_record_add( req.db, COLL_USERS, { ...u, ...data }, UserKeys );

		return cback ? cback( null, u ) : resolve( u );
		/*=== f2c_end patch_user_admin_fields ===*/
	} );
};
// }}}

// {{{ post_user_register ( req: ILRequest, email: string, password: string, recaptcha: string, name?: string, lastname?: string, phone?: string, username?: string, cback: LCBack = null ): Promise<UserActivationCode>
/**
 *
 * Start the registration process of the user.
 * The call creates an entry inside the database (if no error is encountered)
 * If in **debug mode** this functyion returns  the `UserActivationCode`
 *
 * @param email - the new user email [req]
 * @param password - the user password [req]
 * @param recaptcha - The recaptcha check code [req]
 * @param name - the user first name [opt]
 * @param lastname - the user lastname [opt]
 * @param phone - the user phone [opt]
 * @param username - The user username [opt]
 *
 * @return uac: UserActivationCode
 *
 */
export const post_user_register = ( req: ILRequest, email: string, password: string, recaptcha: string, name?: string, lastname?: string, phone?: string, username?: string, cback: LCback = null ): Promise<UserActivationCode> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_register ===*/
		const err = { message: _( 'Invalid parameters' ) };

		const rc = await _recaptcha_check( req, recaptcha, err );
		if ( !rc ) return cback ? cback( err ) : reject( err );

		const user: User = await _create_user(
			req,
			err,
			username,
			email,
			phone,
			name,
			lastname,
			password,
		);

		if ( !user ) return cback ? cback( err ) : reject( err );

		_send_validation_code( req, user );

		// if cfg.debug is true, return the activation code
		const code = req.cfg.debug?.enabled && req.cfg.debug?.send_code ? user.code : '';

		return cback ? cback( null, code as any ) : resolve( code as any );
		/*=== f2c_end post_user_register ===*/
	} );
};
// }}}

// {{{ patch_user_update ( req: ILRequest, email?: string, password?: string, name?: string, lastname?: string, cback: LCBack = null ): Promise<User>
/**
 *
 * Updates user data.
 * Only the user can update him/her self.
 *
 * @param email - the new user email [opt]
 * @param password - the user password [opt]
 * @param name - the user name [opt]
 * @param lastname - the user lastname [opt]
 *
 * @return user: User
 *
 */
export const patch_user_update = ( req: ILRequest, email?: string, password?: string, name?: string, lastname?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start patch_user_update ===*/
		let u = await user_get( req.user.id );

		if ( !u ) {
			const err = { message: _( 'User not found' ) };
			return cback ? cback( err ) : reject( err );
		}

		u = { ...u, ...keys_valid( { email, password, name, lastname } ) };

		u = await adb_record_add( req.db, COLL_USERS, u, UserKeys );

		return cback ? cback( null, u ) : resolve( u );
		/*=== f2c_end patch_user_update ===*/
	} );
};
// }}}

// {{{ post_user_avatar ( req: ILRequest, avatar: File, cback: LCBack = null ): Promise<User>
/**
 *
 * Uploads a user avatar.
 * Only the user can update him/her self.
 *
 * @param avatar - The user avatar file [req]
 *
 * @return user: User
 *
 */
export const post_user_avatar = ( req: ILRequest, avatar: File, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_avatar ===*/
		const u: Upload = await upload_add_file_name( req, 'avatar', 'user', req.user.id, 'avatars', null, true );
		let user: User = await user_get( req.user.id );

		user.avatar = u.path;

		user = await adb_record_add( req.db, COLL_USERS, user, UserKeys );

		return cback ? cback( null, user ) : resolve( user );
		/*=== f2c_end post_user_avatar ===*/
	} );
};
// }}}

// {{{ post_user_facerec_add ( req: ILRequest, face: File, cback: LCBack = null ): Promise<UserFaceRec>
/**
 *
 * Uploads a user face for face recognition.
 * Only the user can update him/her self.
 *
 * @param face - the user face photo [req]
 *
 * @return facerec: UserFaceRec
 *
 */
export const post_user_facerec_add = ( req: ILRequest, face: File, cback: LCback = null ): Promise<UserFaceRec> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_facerec_add ===*/
		const u: Upload = await upload_add_file_name( req, 'face', 'user', req.user.id, 'faces' );
		const domain = await system_domain_get_by_session( req );

		let fr: UserFaceRec = { id: mkid( 'face' ), domain: domain.code, id_user: req.user.id, id_upload: u.id, filename: u.filename };

		fr = await adb_record_add( req.db, COLL_USER_FACERECS, fr, UserFaceRecKeys );

		return cback ? cback( null, fr ) : resolve( fr );
		/*=== f2c_end post_user_facerec_add ===*/
	} );
};
// }}}

// {{{ post_user_password_forgot ( req: ILRequest, email: string, recaptcha: string, cback: LCBack = null ): Promise<string>
/**
 *
 * Start the 'Password forgotten' process for the user.
 * The call creates a temporary token for the user.
 * In **debug mode**  returns to the user the activation code as  ``str`` inside ``uac``.
 *
 * @param email - the user email [req]
 * @param recaptcha - the recaptcha verification code [req]
 *
 * @return uac: string
 *
 */
export const post_user_password_forgot = ( req: ILRequest, email: string, recaptcha: string, cback: LCback = null ): Promise<string> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_password_forgot ===*/
		let user: User = await adb_query_one( req.db, `FOR u IN ${ COLL_USERS } FILTER u.email == @email RETURN u`, { email } );
		const err = { message: _( 'User not found' ) };

		const rc = await _recaptcha_check( req, recaptcha, err );
		if ( !rc ) return cback ? cback( err ) : reject( err );

		if ( !user ) {
			add_suspicious_activity( req, req.res, "Password forgot with wrong email" );
			return cback ? cback( err ) : reject( err );
		}

		user.code = random_string( 30, 30, false );

		user = await adb_record_add( req.db, COLL_USERS, user );

		// NOTE: code is sent only if req.cfg.debug is enabled
		const code = req.cfg.debug?.enabled && req.cfg.debug?.send_code ? user.code : '';

		send_mail_template( _( "Password Forgot" ), server_fullpath( "../../etc/templates/user/password-reset.html" ),
			{
				code: user.code,
				site_name: req.cfg.app.name,
				site_base_url: req.cfg.server.public_url,
			}, email, req.cfg.smtp.from, null, null );

		return cback ? cback( null, code ) : resolve( code );
		/*=== f2c_end post_user_password_forgot ===*/
	} );
};
// }}}

// {{{ post_user_password_reset ( req: ILRequest, email: string, code: string, password: string, cback: LCBack = null ): Promise<boolean>
/**
 *
 * Resets the user password.
 *
 * @param email - the user email [req]
 * @param code - the activation code [req]
 * @param password - the new password [req]
 *
 * @return ok: boolean
 *
 */
export const post_user_password_reset = ( req: ILRequest, email: string, code: string, password: string, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_password_reset ===*/
		const user = await adb_query_one( _liwe.db, `FOR u IN ${ COLL_USERS } FILTER u.email == @email RETURN u`, { email } );
		const err = { message: _( 'User not found' ) };
		if ( !user ) {
			add_suspicious_activity( req, req.res, "Password reset request for unknown email address" );
			return cback ? cback( err ) : reject( err );
		}

		err.message = "Wrong confirmation code";
		if ( user.code != code ) {
			add_suspicious_activity( req, req.res, "Password reset request with wrong code" );
			return cback ? cback( err ) : reject( err );
		}

		user.password = sha512( password );

		await adb_record_add( _liwe.db, COLL_USERS, user );

		return cback ? cback( null, true ) : resolve( true );
		/*=== f2c_end post_user_password_reset ===*/
	} );
};
// }}}

// {{{ get_user_register_activate ( req: ILRequest, code: string, cback: LCBack = null ): Promise<User>
/**
 *
 * This is the activation request.
 *
 * @param code - the activation code returned by the /api/register call [req]
 *
 * @return user: User
 *
 */
export const get_user_register_activate = ( req: ILRequest, code: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_register_activate ===*/
		const u: User = await adb_query_one( _liwe.db, `FOR u IN ${ COLL_USERS } FILTER u.code == @code RETURN u`, { code } );
		const err = { message: _( 'User not found' ) };
		if ( !u ) return cback ? cback( err ) : reject( err );

		u.enabled = true;
		// u.visible = true;
		u.code = null;

		await adb_record_add( _liwe.db, COLL_USERS, u );

		return cback ? cback( null, u ) : resolve( u );
		/*=== f2c_end get_user_register_activate ===*/
	} );
};
// }}}

// {{{ post_user_tag ( req: ILRequest, id_user: string, tags: string[], cback: LCBack = null ): Promise<User>
/**
 *
 * This endpoint allows you to add tags to a user.
 *
 * @param id_user - the user id [req]
 * @param tags -  A list of tags to be added to the user [req]
 *
 * @return user: User
 *
 */
export const post_user_tag = ( req: ILRequest, id_user: string, tags: string[], cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_tag ===*/
		let user = await user_get( id_user );

		user = await tag_obj( req, tags, id_user, 'user' ) as any;

		user = await adb_record_add( _liwe.db, COLL_USERS, user );

		return cback ? cback( null, user ) : resolve( user );
		/*=== f2c_end post_user_tag ===*/
	} );
};
// }}}

// {{{ post_user_token ( req: ILRequest, username: string, password: string, cback: LCBack = null ): Promise<UserSessionData>
/**
 *
 * This endpoint implements the user authentication with the ``OAuth2`` protocol.
 * If the user is known, a JWT token with the running session is returned to the system.
 *
 * @param username - it must contain the user email [req]
 * @param password - the user password [req]
 *
 * @return __plain__: UserSessionData
 *
 */
export const post_user_token = ( req: ILRequest, username: string, password: string, cback: LCback = null ): Promise<UserSessionData> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_token ===*/
		const [ filters, values ] = adb_prepare_filters( 'u', { email: username, password: sha512( password ), enabled: true } );
		const u: User = await adb_query_one( _liwe.db, `FOR u IN ${ COLL_USERS } ${ filters } RETURN u`, values );
		const err = { message: _( 'User not found' ) };

		if ( !u ) {
			add_suspicious_activity( req, req.res, 'Token creation for not existent user' );
			return cback ? cback( err ) : reject( err );
		}

		const tok = await user_session_create( req, u );

		const resp: UserSessionData = {
			access_token: tok,
			token_type: 'bearer',
		};

		return cback ? cback( null, resp ) : resolve( resp );
		/*=== f2c_end post_user_token ===*/
	} );
};
// }}}

// {{{ post_user_login ( req: ILRequest, password: string, email?: string, username?: string, recaptcha?: string, challenge?: string, cback: LCBack = null ): Promise<UserSessionData>
/**
 *
 * This endpoint implements the user authentication with ``email`` or ``username`` and ``password`` field.
 * The call must provide also ``recaptcha`` or ``challenge`` in order to verify the validity of the call. \
 * You don't have to provide both, but one is mandatory.
 * If the user is known, a JWT token with the running session is returned to the system.
 *
 * @param password - the user password [req]
 * @param email - The user email [opt]
 * @param username - The username [opt]
 * @param recaptcha - The recaptcha check code [opt]
 * @param challenge - The challenge verification code [opt]
 *
 * @return __plain__: UserSessionData
 *
 */
export const post_user_login = ( req: ILRequest, password: string, email?: string, username?: string, recaptcha?: string, challenge?: string, cback: LCback = null ): Promise<UserSessionData> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_login ===*/
		const err = { message: '' };

		if ( !username && !email ) {
			add_suspicious_activity( req, req.res, 'Username and email not provided' );
			err.message = _( 'Username or email not provided' );
			return cback ? cback( err ) : reject( err );
		}

		if ( !recaptcha && !challenge ) {
			add_suspicious_activity( req, req.res, 'Recaptcha or challenge not provided' );
			err.message = _( 'Recaptcha or challenge not provided' );
			return cback ? cback( err ) : reject( err );
		}

		const user: User = await user_get( undefined, email );

		const rc = await _recaptcha_check( req, recaptcha, err );
		if ( !rc ) return cback ? cback( err ) : reject( err );

		if ( !user ) {
			console.error( "User not found: ", email, password );
			add_suspicious_activity( req, req.res, `User not found ${ email }` );
			return cback ? cback( err ) : reject( err );
		}

		if ( user.enabled === false ) {
			console.error( "User not enabled: ", email );
			add_suspicious_activity( req, req.res, `User not enabled ${ email }` );
			return cback ? cback( err ) : reject( err );
		}

		if ( !_password_check( req, password, user, err, email ) )
			return cback ? cback( err ) : reject( err );

		const tok: any = await user_session_create( req, user );
		const resp: UserSessionData = {
			access_token: tok,
			token_type: 'bearer',
			name: user.name,
			lastname: user.lastname,
		};

		return cback ? cback( null, resp ) : resolve( resp );
		/*=== f2c_end post_user_login ===*/
	} );
};
// }}}

// {{{ post_user_login_remote ( req: ILRequest, email: string, name: string, challenge: string, avatar?: string, cback: LCBack = null ): Promise<UserSessionData>
/**
 *
 * This endpoint logs in a user authenticated by a remote service.
 * Since this is a public call, the `challenge` parameter is used to verify that the call is from the correct service.
 * The `challenge` parameter is a `MD5` hash created composing (`email` + `name` + `remote_secret_key` as set in the `data.json` config file under `security / remote`).
 * The `avatar` parameter is optional and it can contain an absolute URL to an image avatar of the user.
 *
 * @param email - The user email [req]
 * @param name - The user name [req]
 * @param challenge - The challenge [req]
 * @param avatar - The user avatar [opt]
 *
 * @return __plain__: UserSessionData
 *
 */
export const post_user_login_remote = ( req: ILRequest, email: string, name: string, challenge: string, avatar?: string, cback: LCback = null ): Promise<UserSessionData> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_login_remote ===*/
		const err = { message: _( 'Invalid data for user remote login' ) };

		console.log( "\n\n\n==== post_user_login_remote: ", { email, name, challenge, avatar } );

		// Check if the challenge is valid
		if ( !challenge_check( challenge, [ email, name, avatar ] ) )
			return cback ? cback( err ) : reject( err );

		// Check if the user exists
		let user: User = await user_get( undefined, email );

		if ( user ) {
			// If the user is not enabled, we reject the request
			if ( user.enabled === false ) {
				err.message = _( 'User not enabled' );
				add_suspicious_activity( req, req.res, `User not enabled ${ email }` );
				return cback ? cback( err ) : reject( err );
			}
		} else {
			// If we arrive here, it is a new user

			// extract name and lastname from string
			const [ name_, lastname ] = name.split( ' ' );
			user = { id: mkid( 'user' ), email, password: sha512( mkid( 'temp' ) ), name: name_, lastname, enabled: true, language: 'en', avatar };
			user = await adb_record_add( req.db, COLL_USERS, user, UserKeys );
		}

		// If the user exists we create a valid session and return
		const resp: UserSessionData = await _create_user_session( req, user );
		return cback ? cback( null, resp ) : resolve( resp );
		/*=== f2c_end post_user_login_remote ===*/
	} );
};
// }}}

// {{{ get_user_admin_list ( req: ILRequest, tag?: string, cback: LCBack = null ): Promise<User[]>
/**
 *
 * Returns all user registered to the system.
 * If `domain` is specified, the list is filtered by domain.
 * If the user does not have the `system.admin` permission, only the users by his `domain` will be shown.
 * If `tag` is specified, the list is filtered by tag.
 *
 * @param tag -  The tag to filter by [opt]
 *
 * @return users: User
 *
 */
export const get_user_admin_list = ( req: ILRequest, tag?: string, cback: LCback = null ): Promise<User[]> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_admin_list ===*/
		const domain = req.session.domain_code;
		const [ filters, values ] = adb_prepare_filters( "user", {
			domain,
			deleted: {
				mode: 'null'
			},
			tags: {
				mode: 'a',
				val: [ tag ],
				name: 'tags'
			}
		} );

		const users = await adb_query_all( req.db, `FOR user IN ${ COLL_USERS } ${ filters } SORT user.name, user.lastname RETURN user`, values, UserKeys );

		return cback ? cback( null, users ) : resolve( users );
		/*=== f2c_end get_user_admin_list ===*/
	} );
};
// }}}

// {{{ get_user_logout ( req: ILRequest, cback: LCBack = null ): Promise<boolean>
/**
 *
 * This endpoint logs out the current user
 *
 *
 * @return ok: boolean
 *
 */
export const get_user_logout = ( req: ILRequest, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_logout ===*/
		if ( !req.user ) return cback ? cback( null, false ) : resolve( false as any );

		const [ key, sess_id ] = await session_id( req, null );

		await session_del( req, key );

		return cback ? cback( null, true ) : resolve( true as any );
		/*=== f2c_end get_user_logout ===*/
	} );
};
// }}}

// {{{ get_user_me ( req: ILRequest, cback: LCBack = null ): Promise<User>
/**
 *
 * This endpoints returns all data related to the currently logged in user.
 *
 *
 * @return user: User
 *
 */
export const get_user_me = ( req: ILRequest, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_me ===*/
		const err = { message: _( 'User not found' ) };
		const u = await user_get( req.user?.id );

		if ( !u ) return cback ? cback( err ) : reject( err );

		await _addresses_add( req, u );

		keys_filter( u, UserKeys );

		return cback ? cback( null, u ) : resolve( u );
		/*=== f2c_end get_user_me ===*/
	} );
};
// }}}

// {{{ post_user_perms_set ( req: ILRequest, id_user: string, perms: UserPerms, cback: LCBack = null ): Promise<boolean>
/**
 *
 * This endpoint set the full user permissions.
 * The function will allow changing the permsissions only if the request comes from a logged user with the `user.perms` permission set.
 * If the  `system: [ 'admin' ]` permission is set to the user, it becomes a super user and can do **all** operations on the system.
 *
 * @param id_user - The user id [req]
 * @param perms - A JSON of `UserPerms` structure [req]
 *
 * @return ok: boolean
 *
 */
export const post_user_perms_set = ( req: ILRequest, id_user: string, perms: UserPerms, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_perms_set ===*/
		const user = await user_get( id_user );
		const err = { message: _( 'User not found' ) };

		if ( !user ) return cback ? cback( err ) : reject( err );

		user.perms = perms as any;
		await adb_record_add( req.db, COLL_USERS, user );

		return cback ? cback( null, true ) : resolve( true );
		/*=== f2c_end post_user_perms_set ===*/
	} );
};
// }}}

// {{{ post_user_info_add ( req: ILRequest, key: string, data: any, cback: LCBack = null ): Promise<boolean>
/**
 *
 * This endpoint adds extra information inside the `extra` field, under the `key` specified.
 * If `key` was already present in the `extra` field, everything in `key` will be overwritten.
 * New `key`s will be added to `extra`.
 * If `key` is omitted (passing `''`)  the data is added to the `extra` root.
 *
 * @param key - the  main key [req]
 * @param data - the new data to be added [req]
 *
 * @return ok: boolean
 *
 */
export const post_user_info_add = ( req: ILRequest, key: string, data: any, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_info_add ===*/
		const u = await user_get( req.user.id );

		if ( key ) u.extra[ key ] = data;

		await adb_record_add( req.db, COLL_USERS, u );

		return cback ? cback( null, 1 ) : resolve( 1 as any );
		/*=== f2c_end post_user_info_add ===*/
	} );
};
// }}}

// {{{ delete_user_info_del ( req: ILRequest, key: string, cback: LCBack = null ): Promise<boolean>
/**
 *
 * This endpoint deletes the specified `key` from the `extra` field.
 *
 * @param key - The `key` to be deleted [req]
 *
 * @return ok: boolean
 *
 */
export const delete_user_info_del = ( req: ILRequest, key: string, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start delete_user_info_del ===*/
		const u = await user_get( req.user.id );

		u.extra[ key ] = '__@@_invalid_@@__';

		await adb_record_add( req.db, COLL_USERS, u );

		return cback ? cback( null, true ) : resolve( true );
		/*=== f2c_end delete_user_info_del ===*/
	} );
};
// }}}

// {{{ patch_user_profile ( req: ILRequest, name?: string, lastname?: string, phone?: string, email?: string, addr_street?: string, addr_nr?: string, addr_zip?: string, addr_city?: string, addr_state?: string, addr_country?: string, facebook?: string, twitter?: string, linkedin?: string, instagram?: string, website?: string, cback: LCBack = null ): Promise<User>
/**
 *
 * This is the first tab 'Profile' of the UserProfile interface.
 * You can change data only to the current loggedin user.
 *
 * @param name - The user name [opt]
 * @param lastname - The user lastname [opt]
 * @param phone - User phone [opt]
 * @param email - user email [opt]
 * @param addr_street - Address street [opt]
 * @param addr_nr - Address street number [opt]
 * @param addr_zip - Address zip code [opt]
 * @param addr_city - Address city [opt]
 * @param addr_state - Address state (or probvince) [opt]
 * @param addr_country - Address country [opt]
 * @param facebook - Facebook user name [opt]
 * @param twitter - Twitter user name [opt]
 * @param linkedin - Linkedin user name [opt]
 * @param instagram - Instagram user name [opt]
 * @param website - User personal web site [opt]
 *
 * @return user: User
 *
 */
export const patch_user_profile = ( req: ILRequest, name?: string, lastname?: string, phone?: string, email?: string, addr_street?: string, addr_nr?: string, addr_zip?: string, addr_city?: string, addr_state?: string, addr_country?: string, facebook?: string, twitter?: string, linkedin?: string, instagram?: string, website?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start patch_user_profile ===*/
		const err = { message: _( 'User not found' ) };
		let u: User = await user_get( req.user.id );

		if ( !u ) return cback ? cback( err ) : reject( err );

		u = { ...u, ...keys_valid( { name, lastname, phone, facebook, twitter, linkedin, instagram, website } ) };

		await adb_record_add( req.db, COLL_USERS, u );
		await address_add( req, u.id, addr_street, addr_nr, "home", "home", addr_city, addr_zip, addr_state, addr_country, null, null, null, null, null, null, true );

		await _addresses_add( req, u );

		return cback ? cback( null, u ) : resolve( u );
		/*=== f2c_end patch_user_profile ===*/
	} );
};
// }}}

// {{{ get_user_test_create ( req: ILRequest, cback: LCBack = null ): Promise<User>
/**
 *
 * This endpoint creates a demo user
 *
 *
 * @return user: User
 *
 */
export const get_user_test_create = ( req: ILRequest, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_test_create ===*/
		const user = { "email": "mario.rossi@gmail.com", "password": sha512( "Ciao123!" ), "enabled": true, "created": Date(), name: "Mario", lastname: "Rossi" };
		await adb_record_add( req.db, COLL_USERS, user );

		return cback ? cback( null, user ) : resolve( user as any );
		/*=== f2c_end get_user_test_create ===*/
	} );
};
// }}}

// {{{ patch_user_change_password ( req: ILRequest, old_password: string, new_password: string, recaptcha: string, cback: LCBack = null ): Promise<boolean>
/**
 *
 * This is the change password functionality for UserProfile tab.
 * You can change data only to the current loggedin user.
 *
 * @param old_password - the old password [req]
 * @param new_password - the new password [req]
 * @param recaptcha - the recaptcha verfication code [req]
 *
 * @return ok: boolean
 *
 */
export const patch_user_change_password = ( req: ILRequest, old_password: string, new_password: string, recaptcha: string, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start patch_user_change_password ===*/
		const err = { message: _( 'Passwords not matching' ) };

		const valid = await _recaptcha_check( req, recaptcha, err );

		if ( !valid ) return cback ? cback( err ) : reject( err );

		let user: User = await user_get( req.user.id );

		if ( !_password_check( req, old_password, user, err ) )
			return cback ? cback( err ) : reject( err );

		if ( !_valid_password( new_password, err, req.cfg ) )
			return cback ? cback( err ) : reject( err );

		user.password = sha512( new_password, false );

		await adb_record_add( req.db, COLL_USERS, user );

		return cback ? cback( null, true ) : resolve( true );
		/*=== f2c_end patch_user_change_password ===*/
	} );
};
// }}}

// {{{ patch_user_set_bio ( req: ILRequest, tagline?: string, bio?: string, cback: LCBack = null ): Promise<User>
/**
 *
 * Use this endpoint to update user `bio` or `tagline` (or both).
 * The currently logged in user can only change his/her own data.
 *
 * @param tagline - User tagline [opt]
 * @param bio - User bio [opt]
 *
 * @return user: User
 *
 */
export const patch_user_set_bio = ( req: ILRequest, tagline?: string, bio?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start patch_user_set_bio ===*/
		let user: User = await user_get( req.user.id );

		if ( tagline ) user.tagline = tagline;
		if ( bio ) user.bio = bio;

		user = await adb_record_add( req.db, COLL_USERS, user, UserKeys );

		return cback ? cback( null, user ) : resolve( user );
		/*=== f2c_end patch_user_set_bio ===*/
	} );
};
// }}}

// {{{ patch_user_set_billing ( req: ILRequest, address?: string, nr?: string, name?: string, city?: string, zip?: string, state?: string, country?: string, company_name?: string, fiscal_code?: string, vat_number?: string, sdi?: string, pec?: string, cback: LCBack = null ): Promise<User>
/**
 *
 * Creates / updates the user billing info.
 * You can change data only to the current loggedin user.
 *
 * @param address - The street address [opt]
 * @param nr - The street address number [opt]
 * @param name - Address name [opt]
 * @param city - Address city [opt]
 * @param zip - Address postal code [opt]
 * @param state - Address state [opt]
 * @param country - Address country [opt]
 * @param company_name - Company name [opt]
 * @param fiscal_code - Fiscal code [opt]
 * @param vat_number - VAT number [opt]
 * @param sdi - SDI code [opt]
 * @param pec - PEC email [opt]
 *
 * @return user: User
 *
 */
export const patch_user_set_billing = ( req: ILRequest, address?: string, nr?: string, name?: string, city?: string, zip?: string, state?: string, country?: string, company_name?: string, fiscal_code?: string, vat_number?: string, sdi?: string, pec?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start patch_user_set_billing ===*/
		await address_add( req, req.user.id, address, nr, 'Invoice info', 'invoice', city, zip, state, country, company_name, fiscal_code, vat_number, sdi, pec, null, true );

		const user: User = await user_get( req.user.id );
		await _addresses_add( req, user );

		keys_filter( user, UserKeys );

		return cback ? cback( null, user ) : resolve( user );
		/*=== f2c_end patch_user_set_billing ===*/
	} );
};
// }}}

// {{{ post_user_login_metamask ( req: ILRequest, address: string, challenge: string, cback: LCBack = null ): Promise<UserSessionData>
/**
 *
 * This endpoint logs in a user authenticated by a remote service.
 * Since this is a public call, the `challenge` parameter is used to verify that the call is from the correct service.
 * The `challenge` parameter is a `MD5` hash created composing (`address` + `remote_secret_key` as set in the `data.json` config file under `security / remote`).
 *
 * @param address - The wallet address [req]
 * @param challenge - The challenge [req]
 *
 * @return __plain__: UserSessionData
 *
 */
export const post_user_login_metamask = ( req: ILRequest, address: string, challenge: string, cback: LCback = null ): Promise<UserSessionData> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_login_metamask ===*/
		const err = { message: _( 'Invalid data for user remote login' ) };

		console.log( "\n\n\n==== post_user_login_metamask: ", { address, challenge } );

		// Check if the challenge is valid
		if ( !challenge_check( challenge, [ address ] ) )
			return cback ? cback( err ) : reject( err );

		// Check if the user exists
		let user: User = await user_get( undefined, undefined, address );

		if ( !user ) {
			err.message = _( 'User not found' );
			return cback ? cback( err ) : reject( err );
		}

		if ( user ) {
			// If the user is not enabled, we reject the request
			if ( user.enabled === false ) {
				err.message = _( 'User not enabled' );
				add_suspicious_activity( req, req.res, `User not enabled ${ user.email }` );
				return cback ? cback( err ) : reject( err );
			}
		}

		// If the user exists we create a valid session and return
		const resp: UserSessionData = await _create_user_session( req, user );
		return cback ? cback( null, resp ) : resolve( resp );
		/*=== f2c_end post_user_login_metamask ===*/
	} );
};
// }}}

// {{{ get_user_admin_get ( req: ILRequest, id?: string, email?: string, name?: string, lastname?: string, cback: LCBack = null ): Promise<User>
/**
 *
 * This method can return a user after searching all users by some params.
 * Params are all optional, but at least one must be given, or the current user will be returned.
 * If the search returns more than one single user, only the first will be returned.
 *
 * @param id - The user id [opt]
 * @param email - The user email [opt]
 * @param name - The user name [opt]
 * @param lastname - The user lastname [opt]
 *
 * @return user: User
 *
 */
export const get_user_admin_get = ( req: ILRequest, id?: string, email?: string, name?: string, lastname?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_admin_get ===*/
		const [ filters, values ] = adb_prepare_filters( 'u', { id, email, name, lastname } );
		let user: User = null;

		if ( !Object.keys( filters ).length ) {
			user = await user_get( req.user.id );
		} else {
			user = await adb_query_one( req.db, `
			FOR u IN users
				${ filters }
				RETURN u`, values );
		}

		if ( !user ) user = {};

		keys_filter( user, UserKeys );

		return cback ? cback( null, user ) : resolve( user );
		/*=== f2c_end get_user_admin_get ===*/
	} );
};
// }}}

// {{{ get_user_remove_me ( req: ILRequest, cback: LCBack = null ): Promise<boolean>
/**
 *
 * This method removes the current user from the system
 *
 *
 * @return ok: boolean
 *
 */
export const get_user_remove_me = ( req: ILRequest, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_remove_me ===*/
		let u: User = await user_get( req.user.id );

		u.enabled = false;

		await adb_record_add( req.db, COLL_USERS, u );
		await get_user_logout( req );

		return cback ? cback( null, true ) : resolve( true );
		/*=== f2c_end get_user_remove_me ===*/
	} );
};
// }}}

// {{{ get_user_perms_get ( req: ILRequest, id_user: string, cback: LCBack = null ): Promise<boolean>
/**
 *
 * This endpoint set returns full user permissions.
 *
 * @param id_user - The user id [req]
 *
 * @return ok: boolean
 *
 */
export const get_user_perms_get = ( req: ILRequest, id_user: string, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_perms_get ===*/
		const err = { message: _( 'User not found' ) };
		const user: User = await user_get( id_user );

		if ( !user ) return cback ? cback( err ) : reject( err );

		return cback ? cback( null, user.perms ) : resolve( user.perms );
		/*=== f2c_end get_user_perms_get ===*/
	} );
};
// }}}

// {{{ get_user_faces_get ( req: ILRequest, id_user?: string, cback: LCBack = null ): Promise<UserFaceRec[]>
/**
 *
 * Return all images available for face recognition
 * If the `id_user` is not specified, the current logged user faces are returned.
 * If the `id_user` is specified, but the user does not have the `user.create` permission, the `id_user` will be the one of the currently logged user.
 *
 * @param id_user - The User ID to get faces for [opt]
 *
 * @return faces: UserFaceRec
 *
 */
export const get_user_faces_get = ( req: ILRequest, id_user?: string, cback: LCback = null ): Promise<UserFaceRec[]> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_faces_get ===*/
		if ( !id_user ) id_user = req.user.id;

		if ( !perm_available( req.user, [ 'user.create' ] ) ) id_user = req.user.id;

		const faces: UserFaceRec[] = await adb_find_all( req.db, COLL_USER_FACERECS, { id_user }, UserFaceRecKeys );

		return cback ? cback( null, faces ) : resolve( faces );
		/*=== f2c_end get_user_faces_get ===*/
	} );
};
// }}}

// {{{ post_user_upload2face ( req: ILRequest, id_upload: string, id_user?: string, cback: LCBack = null ): Promise<UserFaceRec>
/**
 *
 * @param id_upload - The ID Upload [req]
 * @param id_user - The user id [opt]
 *
 * @return face: UserFaceRec
 *
 */
export const post_user_upload2face = ( req: ILRequest, id_upload: string, id_user?: string, cback: LCback = null ): Promise<UserFaceRec> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_upload2face ===*/
		if ( !id_user ) id_user = req.user.id;

		if ( !perm_available( req.user, [ 'user.create' ] ) ) id_user = req.user.id;

		const upload: Upload = await upload_get( id_upload );

		if ( !upload ) return cback ? cback( { message: _( 'Upload not found' ) } ) : reject( { message: _( 'Upload not found' ) } );

		// deletes old entry if exists
		await adb_del_one( req.db, COLL_USER_FACERECS, { id_user, id_upload } );

		// add new entry
		const face: UserFaceRec = {
			id: mkid( 'face' ),
			id_user,
			id_upload,
			domain: upload.domain,
			filename: upload.filename,
			path: upload.path,
		};

		await adb_record_add( req.db, COLL_USER_FACERECS, face, UserFaceRecKeys );

		return cback ? cback( null, face ) : resolve( face );
		/*=== f2c_end post_user_upload2face ===*/
	} );
};
// }}}

// {{{ get_user_faces_modules ( req: ILRequest, cback: LCBack = null ): Promise<boolean>
/**
 *
 *
 * @return ok: boolean
 *
 */
export const get_user_faces_modules = ( req: ILRequest, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_faces_modules ===*/

		/*=== f2c_end get_user_faces_modules ===*/
	} );
};
// }}}

// {{{ post_user_anonymous ( req: ILRequest, ts: string, challenge: string, cback: LCBack = null ): Promise<User>
/**
 *
 * This method is used when you need a temporary session for a user.
 * It creates a *real* user in the database, with fake data.
 * Users have a 24 hours life span, if not converted into "real" users, they are deleted.
 *
 * @param ts - The generated random number [req]
 * @param challenge - The challenge [req]
 *
 * @return user: User
 *
 */
export const post_user_anonymous = ( req: ILRequest, ts: string, challenge: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_anonymous ===*/
		const valid = challenge_check( challenge, [ ts ] );
		const err = { message: _( 'Invalid challenge' ) };

		if ( !valid ) return cback ? cback( err ) : reject( err );

		const user: User = user_create( `${ ts }@anonymous.me`, challenge, 'guest', 'user', true, 'it' );

		await adb_record_add( req.db, COLL_USERS, user, UserKeys );
		/*=== f2c_end post_user_anonymous ===*/
	} );
};
// }}}

// {{{ post_user_register_app ( req: ILRequest, email: string, password: string, challenge: string, name?: string, lastname?: string, phone?: string, username?: string, cback: LCBack = null ): Promise<UserActivationCode>
/**
 *
 * Start the registration process of the user replacing the rechapta with a challenge code.
 * The call creates an entry inside the database (if no error is encountered)
 * If in **debug mode** this functyion returns  the `UserActivationCode`
 *
 * @param email - the new user email [req]
 * @param password - the user password [req]
 * @param challenge - The challenge code [req]
 * @param name - the user first name [opt]
 * @param lastname - the user lastname [opt]
 * @param phone - the user phone [opt]
 * @param username - The user username [opt]
 *
 * @return uac: UserActivationCode
 *
 */
export const post_user_register_app = ( req: ILRequest, email: string, password: string, challenge: string, name?: string, lastname?: string, phone?: string, username?: string, cback: LCback = null ): Promise<UserActivationCode> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start post_user_register_app ===*/
		const challenge_fields = [ email, password, name, lastname, phone, username ];
		const check_challenge = challenge_create( challenge_fields, true );
		const err = { message: _( 'Invalid challenge' ) };

		if ( check_challenge != challenge ) {
			error( 'Invalid challenge', { received: challenge, expected: check_challenge } );
			return cback ? cback( err ) : reject( err );
		}

		const user: User = await _create_user(
			req,
			err,
			username,
			email,
			phone,
			name,
			lastname,
			password );

		if ( !user ) return cback ? cback( err ) : reject( err );

		_send_validation_code( req, user );

		console.log( "\n\n==== CODE: ", user.code );
		keys_filter( user, UserKeys );

		return cback ? cback( null, user ) : resolve( user );
		/*=== f2c_end post_user_register_app ===*/
	} );
};
// }}}

// {{{ get_user_find ( req: ILRequest, search?: string, cback: LCBack = null ): Promise<UserDetails>
/**
 *
 * This endpoints allows the search of a user in the system.
 * You can search only for one these fields at a time:
 * - `email`
 * - `username`
 * and both these fields are considered complete strings and not partials.
 * The `search` parameter will search in both fields at the same time.
 *
 * @param search - The user email [opt]
 *
 * @return user: UserDetails
 *
 */
export const get_user_find = ( req: ILRequest, search?: string, cback: LCback = null ): Promise<UserDetails> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start get_user_find ===*/
		const user: UserDetails = await adb_query_one( req.db, `
		FOR u IN users
			FILTER u.email == @search OR u.username == @search
			RETURN u
		`, { search }, UserDetailsKeys );

		return cback ? cback( null, user ) : resolve( user );
		/*=== f2c_end get_user_find ===*/
	} );
};
// }}}

// {{{ user_facerec_get ( req: ILRequest, id_user: string, cback: LCBack = null ): Promise<UserFaceRec[]>
/**
 *
 * Gets all Face Recs binded to a user
 *
 * @param req - The ILRequest [req]
 * @param id_user - ID user [req]
 *
 * @return : UserFaceRec
 *
 */
export const user_facerec_get = ( req: ILRequest, id_user: string, cback: LCback = null ): Promise<UserFaceRec[]> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start user_facerec_get ===*/
		const faces: UserFaceRec[] = await adb_find_all( req.db, COLL_USER_FACERECS, { id_user }, UserFaceRecKeys );

		return cback ? cback( null, faces ) : resolve( faces );
		/*=== f2c_end user_facerec_get ===*/
	} );
};
// }}}

// {{{ user_session_del ( req: ILiWE, key: string, cback: LCBack = null ): Promise<boolean>
/**
 *
 * Removes a session from the system.
 *
 * @param req - The ILRequest [req]
 * @param key - The Session key [req]
 *
 * @return : boolean
 *
 */
export const user_session_del = ( req: ILiWE, key: string, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start user_session_del ===*/
		const s = "FOR el IN sessions FILTER el.key == @key REMOVE el IN sessions";
		await _liwe.db.query( s, { key } );

		return cback ? cback( null, true ) : resolve( true );
		/*=== f2c_end user_session_del ===*/
	} );
};
// }}}

// {{{ user_session_get ( req: ILRequest, tok: string, cback: LCBack = null ): Promise<any>
/**
 *
 * This function retrieves the session from the sessions collection, using the JWT token provided.
 * If the session is expired or does not exists, an empty object is returned.
 *
 * @param req - The ILRequest [req]
 * @param tok - The JSON Web Token to decode [req]
 *
 * @return : any
 *
 */
export const user_session_get = ( req: ILRequest, tok: string, cback: LCback = null ): Promise<any> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start user_session_get ===*/
		const payload = jwt_decrypt( tok, _liwe.cfg.security.secret );
		const err = { message: _( 'Session expired' ) };

		if ( !payload ) return cback ? cback( err ) : reject( err );

		const [ key, sess_id ] = await session_id( req, payload );

		const data = await session_get( req, key );

		err.message = _( 'Session not found' );
		if ( !data ) return cback ? cback( err ) : reject( err );

		return cback ? cback( null, data ) : resolve( data );
		/*=== f2c_end user_session_get ===*/
	} );
};
// }}}

// {{{ user_session_create ( req: ILRequest, user: User, cback: LCBack = null ): Promise<string>
/**
 *
 * This function creates a new entry in the sessions collection.
 * If a session for the given user already exists, it will be deleted.
 * **NOTE** There cannot be more than one session for a given user / email at a time.
 *
 * @param req - The ILRequest [req]
 * @param user - The user to create the session to [req]
 *
 * @return : string
 *
 */
export const user_session_create = ( req: ILRequest, user: User, cback: LCback = null ): Promise<string> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== f2c_start user_session_create ===*/
		const [ key, sess_id ] = await session_id( req, user.id );

		if ( req.cfg.security?.session?.single )
			await session_remove_all( req, sess_id );

		// We save the sess_id inside the token, not the session_key, because the key is
		// calculated by `session_id()` call
		const tok = jwt_crypt( sess_id, _liwe.cfg.security.secret, _liwe.cfg.security.token_expires );

		const data = {
			user: {
				id: user.id,
				domain: user.domain,
				name: user.name,
				lastname: user.lastname,
				email: user.email,
				perms: user.perms,
				session_key: key
			}
		};

		await session_create( req, key, user.domain, data );

		return cback ? cback( null, tok ) : resolve( tok );
		/*=== f2c_end user_session_create ===*/
	} );
};
// }}}

// {{{ user_db_init ( liwe: ILiWE, cback: LCBack = null ): Promise<boolean>
/**
 *
 * Initializes the module's database
 *
 * @param liwe - The Liwe object [req]
 *
 * @return : boolean
 *
 */
export const user_db_init = ( liwe: ILiWE, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		_liwe = liwe;

		await adb_collection_init( liwe.db, COLL_USER_FACERECS, [
			{ type: "persistent", fields: [ "id" ], unique: true },
			{ type: "persistent", fields: [ "domain" ], unique: false },
			{ type: "persistent", fields: [ "id_user" ], unique: false },
			{ type: "persistent", fields: [ "id_upload" ], unique: true },
		], { drop: false } );

		await adb_collection_init( liwe.db, COLL_USERS, [
			{ type: "persistent", fields: [ "id" ], unique: true },
			{ type: "persistent", fields: [ "domain" ], unique: false },
			{ type: "persistent", fields: [ "email" ], unique: true },
			{ type: "persistent", fields: [ "username" ], unique: true },
			{ type: "persistent", fields: [ "enabled" ], unique: false },
			{ type: "persistent", fields: [ "phone" ], unique: false },
			{ type: "persistent", fields: [ "tags[*]" ], unique: false },
			{ type: "persistent", fields: [ "id_upload" ], unique: false },
			{ type: "persistent", fields: [ "deleted" ], unique: false },
		], { drop: false } );

		/*=== f2c_start user_db_init ===*/

		// Create system users
		await Promise.all( _liwe.cfg.user.users.map( async ( u: any ) => {
			u.password = sha512( u.password );
			u.id = mkid( 'user' );
			delete u.u_id;
			const ck = await adb_query_one( liwe.db, `FOR u IN ${ COLL_USERS } FILTER u.email == @email RETURN u.id`, { email: u.email } );
			if ( ck ) return true;

			return adb_record_add( liwe.db, COLL_USERS, u );
		} ) );

		return cback ? cback( null, _liwe.db ) : resolve( _liwe.db );
		/*=== f2c_end user_db_init ===*/
	} );
};
// }}}


