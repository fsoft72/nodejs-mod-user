
import { ILRequest, ILResponse, LCback, ILiweConfig, ILError, ILiWE } from '../../liwe/types';
import { collection_add, collection_count, collection_find_all, collection_find_by_id, collection_find_one, collection_find_one_dict, collection_find_all_dict, collection_del_one_dict, collection_del_all_dict, collection_init, mkid, prepare_filters } from '../../liwe/arangodb';
import { DocumentCollection } from 'arangojs/collection';
import { $l } from '../../liwe/locale';

import {
	User, UserActivationCode, UserActivationCodeKeys, UserFaceRec, UserFaceRecKeys, UserKeys, UserPerms, UserPermsKeys, UserRegistration, UserRegistrationKeys, UserSessionData, UserSessionDataKeys
} from './types';

let _liwe: ILiWE = null;

const _ = ( txt: string, vals: any = null, plural = false ) => {
	return $l( txt, vals, plural, "user" );
};

let _coll_user_facerecs: DocumentCollection = null;
let _coll_users: DocumentCollection = null;

const COLL_USER_FACERECS = "user_facerecs";
const COLL_USERS = "users";

/*=== d2r_start __file_header === */
import { challenge_check, isValidEmail, jwt_crypt, jwt_decrypt, keys_filter, keys_valid, random_string, recaptcha_check, set_attr, sha512, unique_code } from '../../liwe/utils';
import { tag_obj } from '../tag/methods';
import { add_suspicious_activity } from '../../liwe/defender';
import { send_mail_template } from '../../liwe/mail';
import { server_fullpath, upload_fullpath } from '../../liwe/liwe';

import { SystemDomain } from '../system/types';
import { system_domain_get_by_code, system_domain_get_by_session } from '../system/methods';
import { session_create, session_del, session_get, session_id, session_remove_all } from '../session/methods';
import { upload_add_file_name, upload_del_file } from '../upload/methods';
import { Upload } from '../upload/types';
import { address_add, address_user_list } from '../address/methods';
import { Address } from '../address/types';

export const user_get = async ( id?: string, email?: string, facerec?: boolean ): Promise<User> => {
	const [ filters, values ] = prepare_filters( 'u', { id, email } );

	if ( !filters.length ) return null;

	const user: User = await collection_find_one( _liwe.db, `FOR u IN ${ COLL_USERS } ${ filters } RETURN u`, values );

	if ( !user ) return null;

	if ( !user.extra ) user.extra = '{}';

	if ( typeof user.extra === 'string' )
		user.extra = JSON.parse( user.extra );

	if ( facerec )
		user.faces = await user_facerec_get( { db: _liwe.db } as ILRequest, user.id );

	return user;
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
	const up: Upload = await upload_add_file_name( req, 'avatar', 'user', u.id, 'avatars', null, false, null, u );

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
		name: user.name,
		lastname: user.lastname,
	};

	return resp;
};
/*=== d2r_end __file_header ===*/

// {{{ post_user_admin_add ( req: ILRequest, email: string, password: string, name?: string, lastname?: string, perms?: string[], enabled?: boolean, language?: string, cback: LCBack = null ): Promise<User>
/**
 * Creates a new user in the system
 *
 * @param email - The user email [req]
 * @param password - The user password [req]
 * @param name - The user first name [opt]
 * @param lastname - The user lastname [opt]
 * @param perms - User permissions [opt]
 * @param enabled - Flag T/F to know if the user is enabled [opt]
 * @param language - The user language [opt]
 *
 */
export const post_user_admin_add = ( req: ILRequest, email: string, password: string, name?: string, lastname?: string, perms?: string[], enabled?: boolean, language?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_admin_add ===*/
		email = email.toLowerCase();

		let u: User = await user_get( null, email );
		const err = { message: _( 'User already exists in the system' ) };
		if ( u ) return cback ? cback( err ) : reject( err );

		if ( !_valid_password( password, err, req.cfg ) )
			return cback ? cback( err ) : reject( err );

		u = { id: mkid( 'user' ), email, password: sha512( password ), name, lastname, enabled, language };

		// await _avatar_upload( req, u );

		u = await collection_add( _coll_users, u, false, UserKeys );

		return cback ? cback( null, u ) : resolve( u );
		/*=== d2r_end post_user_admin_add ===*/
	} );
};
// }}}

// {{{ patch_user_admin_update ( req: ILRequest, id: string, email?: string, password?: string, name?: string, lastname?: string, enabled?: boolean, level?: number, language?: string, cback: LCBack = null ): Promise<User>
/**
 * Updates a specified user
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
 */
export const patch_user_admin_update = ( req: ILRequest, id: string, email?: string, password?: string, name?: string, lastname?: string, enabled?: boolean, level?: number, language?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start patch_user_admin_update ===*/
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
		// await _avatar_upload( req, u );
		u = await collection_add( _coll_users, u, false, UserKeys );

		return cback ? cback( null, u ) : resolve( u );
		/*=== d2r_end patch_user_admin_update ===*/
	} );
};
// }}}

// {{{ delete_user_admin_del ( req: ILRequest, id_user: string, cback: LCBack = null ): Promise<string>
/**
 * Deletes a user from the system
 *
 * @param id_user - The user ID [req]
 *
 */
export const delete_user_admin_del = ( req: ILRequest, id_user: string, cback: LCback = null ): Promise<string> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start delete_user_admin_del ===*/
		const u: User = await user_get( id_user );
		const err = { message: _( 'User not found' ) };

		if ( !u ) return cback ? cback( err ) : reject( err );

		const d = new Date().toISOString().split( "T" )[ 0 ];

		u.email = `${ u.email }-${ d }`;
		u.enabled = false;
		u.deleted = new Date();

		await collection_add( _coll_users, u );

		return cback ? cback( null, id_user ) : resolve( id_user );
		/*=== d2r_end delete_user_admin_del ===*/
	} );
};
// }}}

// {{{ patch_user_admin_fields ( req: ILRequest, id: string, data: any, cback: LCBack = null ): Promise<User>
/**
 * Modifies single fields
 *
 * @param id - The post ID [req]
 * @param data - The field / value to patch [req]
 *
 */
export const patch_user_admin_fields = ( req: ILRequest, id: string, data: any, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start patch_user_admin_fields ===*/

		/*=== d2r_end patch_user_admin_fields ===*/
	} );
};
// }}}

// {{{ post_user_register ( req: ILRequest, email: string, password: string, recaptcha: string, name?: string, lastname?: string, cback: LCBack = null ): Promise<UserActivationCode>
/**
 * Start the registration process
 *
 * @param email - the new user email [req]
 * @param password - the user password [req]
 * @param recaptcha - The recaptcha check code [req]
 * @param name - the user first name [opt]
 * @param lastname - the user lastname [opt]
 *
 */
export const post_user_register = ( req: ILRequest, email: string, password: string, recaptcha: string, name?: string, lastname?: string, cback: LCback = null ): Promise<UserActivationCode> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_register ===*/
		const domain = '__system__';
		const err = { message: _( "Invalid domain '{{ domain }}'", { domain } ) };
		const sd: SystemDomain = await system_domain_get_by_code( domain );
		if ( !sd ) return cback ? cback( err ) : reject( err );

		const rc = await _recaptcha_check( req, recaptcha, err );
		if ( !rc ) return cback ? cback( err ) : reject( err );

		err.message = _( 'Invalid parameters' );

		let code = unique_code();
		const dct = { email, password: sha512( password ), name, lastname, enabled: false, visible: false, code, id_domain: sd.id, id: mkid( 'user' ) };

		if ( !isValidEmail( email ) ) return cback ? cback( err ) : reject( err );

		let u = await user_get( undefined, email );
		if ( u ) {
			add_suspicious_activity( req, req.res, 'Using same email for registration' );
			console.error( "ERROR: user %s already exists", email );
			return cback ? cback( err ) : reject( err );
		}

		if ( !_valid_password( password, err, req.cfg ) ) {
			console.error( "ERROR: password for user %s not valid: %s", email, password );
			return cback ? cback( err ) : reject( err );
		}

		const res = await collection_add( _coll_users, dct );

		return cback ? cback( null, code as any ) : resolve( code as any );
		/*=== d2r_end post_user_register ===*/
	} );
};
// }}}

// {{{ patch_user_update ( req: ILRequest, email?: string, password?: string, name?: string, lastname?: string, cback: LCBack = null ): Promise<User>
/**
 * Updates the user data
 *
 * @param email - the new user email [opt]
 * @param password - the user password [opt]
 * @param name - the user first name [opt]
 * @param lastname - the user lastname [opt]
 *
 */
export const patch_user_update = ( req: ILRequest, email?: string, password?: string, name?: string, lastname?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start patch_user_update ===*/

		/*=== d2r_end patch_user_update ===*/
	} );
};
// }}}

// {{{ post_user_avatar ( req: ILRequest, avatar: File, cback: LCBack = null ): Promise<User>
/**
 * Uploads user avatar
 *
 * @param avatar - the user avatar file [req]
 *
 */
export const post_user_avatar = ( req: ILRequest, avatar: File, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_avatar ===*/
		const u: Upload = await upload_add_file_name( req, 'avatar', 'user', req.user.id, 'avatars', null, true );
		let user: User = await user_get( req.user.id );

		user.avatar = u.path;

		user = await collection_add( _coll_users, user, false, UserKeys );

		return cback ? cback( null, user ) : resolve( user );
		/*=== d2r_end post_user_avatar ===*/
	} );
};
// }}}

// {{{ post_user_facerec_add ( req: ILRequest, face: File, cback: LCBack = null ): Promise<UserFaceRec>
/**
 * Uploads user face
 *
 * @param face - the user face photo [req]
 *
 */
export const post_user_facerec_add = ( req: ILRequest, face: File, cback: LCback = null ): Promise<UserFaceRec> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_facerec_add ===*/
		const u: Upload = await upload_add_file_name( req, 'face', 'user', req.user.id, 'faces' );
		const domain = await system_domain_get_by_session( req );

		let fr: UserFaceRec = { id: mkid( 'face' ), domain: domain.code, id_user: req.user.id, id_upload: u.id, filename: u.filename };

		fr = await collection_add( _coll_user_facerecs, fr, false, UserFaceRecKeys );

		return cback ? cback( null, fr ) : resolve( fr );
		/*=== d2r_end post_user_facerec_add ===*/
	} );
};
// }}}

// {{{ post_user_password_forgot ( req: ILRequest, email: string, recaptcha: string, cback: LCBack = null ): Promise<string>
/**
 * Start the 'Forgot password?' process
 *
 * @param email - the new user email [req]
 * @param recaptcha - The recaptcha check code [req]
 *
 */
export const post_user_password_forgot = ( req: ILRequest, email: string, recaptcha: string, cback: LCback = null ): Promise<string> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_password_forgot ===*/
		let user: User = await collection_find_one( req.db, `FOR u IN ${ COLL_USERS } FILTER u.email == @email RETURN u`, { email } );
		const err = { message: _( 'User not found' ) };

		const rc = await _recaptcha_check( req, recaptcha, err );
		if ( !rc ) return cback ? cback( err ) : reject( err );

		if ( !user ) {
			add_suspicious_activity( req, req.res, "Password forgot with wrong email" );
			return cback ? cback( err ) : reject( err );
		}

		user.code = random_string( 30, 30, false );

		user = await collection_add( _coll_users, user );

		// NOTE: code is sent only if req.cfg.debug is enabled
		const code = req.cfg.debug?.enabled && req.cfg.debug?.send_code ? user.code : '';

		send_mail_template( _( "Password Forgot" ), server_fullpath( "../../etc/templates/user/password-reset.html" ),
			{
				code: user.code,
				site_name: req.cfg.app.name,
				site_base_url: req.cfg.server.public_url,
			}, email, req.cfg.smtp.from, null, null );

		return cback ? cback( null, code ) : resolve( code );
		/*=== d2r_end post_user_password_forgot ===*/
	} );
};
// }}}

// {{{ post_user_password_reset ( req: ILRequest, email: string, code: string, password: string, cback: LCBack = null ): Promise<boolean>
/**
 * Reset the password
 *
 * @param email - the user email [req]
 * @param code - the activation code [req]
 * @param password - the new password [req]
 *
 */
export const post_user_password_reset = ( req: ILRequest, email: string, code: string, password: string, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_password_reset ===*/
		const user = await collection_find_one( _liwe.db, `FOR u IN ${ COLL_USERS } FILTER u.email == @email RETURN u`, { email } );
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

		await collection_add( _coll_users, user );

		return cback ? cback( null, true ) : resolve( true );
		/*=== d2r_end post_user_password_reset ===*/
	} );
};
// }}}

// {{{ get_user_register_activate ( req: ILRequest, code: string, cback: LCBack = null ): Promise<User>
/**
 * Activate the user
 *
 * @param code - the activation code returned by the /api/register call [req]
 *
 */
export const get_user_register_activate = ( req: ILRequest, code: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start get_user_register_activate ===*/
		const u: User = await collection_find_one( _liwe.db, `FOR u IN ${ COLL_USERS } FILTER u.code == @code RETURN u`, { code } );
		const err = { message: _( 'User not found' ) };
		if ( !u ) return cback ? cback( err ) : reject( err );

		u.enabled = true;
		// u.visible = true;
		u.code = null;

		await collection_add( _coll_users, u );

		return cback ? cback( null, u ) : resolve( u );
		/*=== d2r_end get_user_register_activate ===*/
	} );
};
// }}}

// {{{ post_user_tag ( req: ILRequest, id_user: string, tags: string[], cback: LCBack = null ): Promise<User>
/**
 * Tag an user
 *
 * @param id_user - The user ID [req]
 * @param tags - A list of tags to be added to the user [req]
 *
 */
export const post_user_tag = ( req: ILRequest, id_user: string, tags: string[], cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_tag ===*/
		let user = await user_get( id_user );

		user = await tag_obj( req, tags, user, 'user' ) as any;

		user = await collection_add( _coll_users, user );

		return cback ? cback( null, user ) : resolve( user );
		/*=== d2r_end post_user_tag ===*/
	} );
};
// }}}

// {{{ post_user_token ( req: ILRequest, username: string, password: string, cback: LCBack = null ): Promise<UserSessionData>
/**
 * User authentication with OAuth2
 *
 * @param username - it must contain the user email [req]
 * @param password - the user password [req]
 *
 */
export const post_user_token = ( req: ILRequest, username: string, password: string, cback: LCback = null ): Promise<UserSessionData> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_token ===*/
		const [ filters, values ] = prepare_filters( 'u', { email: username, password: sha512( password ), enabled: true } );
		const u: User = await collection_find_one( _liwe.db, `FOR u IN ${ COLL_USERS } ${ filters } RETURN u`, values );
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
		/*=== d2r_end post_user_token ===*/
	} );
};
// }}}

// {{{ post_user_login ( req: ILRequest, email: string, password: string, recaptcha: string, cback: LCBack = null ): Promise<UserSessionData>
/**
 * Standard user login
 *
 * @param email - The user email [req]
 * @param password - the user password [req]
 * @param recaptcha - The recaptcha check code [req]
 *
 */
export const post_user_login = ( req: ILRequest, email: string, password: string, recaptcha: string, cback: LCback = null ): Promise<UserSessionData> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_login ===*/
		const user: User = await user_get( undefined, email );
		const err = { message: _( 'Invalid login or password' ) };

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

		const resp: UserSessionData = await _create_user_session( req, user );

		return cback ? cback( null, resp ) : resolve( resp );
		/*=== d2r_end post_user_login ===*/
	} );
};
// }}}

// {{{ post_user_login_remote ( req: ILRequest, email: string, name: string, challenge: string, avatar?: string, cback: LCBack = null ): Promise<UserSessionData>
/**
 * Standard user login
 *
 * @param email - The user email [req]
 * @param name - The user name [req]
 * @param challenge - The challenge [req]
 * @param avatar - The user avatar [opt]
 *
 */
export const post_user_login_remote = ( req: ILRequest, email: string, name: string, challenge: string, avatar?: string, cback: LCback = null ): Promise<UserSessionData> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_login_remote ===*/
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
			user = await collection_add( _coll_users, user, false, UserKeys );
		}

		// If the user exists we create a valid session and return
		const resp: UserSessionData = await _create_user_session( req, user );
		return cback ? cback( null, resp ) : resolve( resp );
		/*=== d2r_end post_user_login_remote ===*/
	} );
};
// }}}

// {{{ get_user_admin_list ( req: ILRequest, tag?: string, cback: LCBack = null ): Promise<User[]>
/**
 * List users to the system
 *
 * @param tag - The tag to filter by [opt]
 *
 */
export const get_user_admin_list = ( req: ILRequest, tag?: string, cback: LCback = null ): Promise<User[]> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start get_user_admin_list ===*/
		const domain = req.session.domain_code;
		const [ filters, values ] = prepare_filters( "user", {
			domain,
			tags: {
				name: 'tags',
				val: tag,
				mode: 'm'
			},
			deleted: {
				mode: 'null'
			}
		} );

		values.tag = tag;

		const users = await collection_find_all( req.db, `FOR user IN ${ COLL_USERS } ${ filters } RETURN user`, values, UserKeys );

		return cback ? cback( null, users ) : resolve( users );
		/*=== d2r_end get_user_admin_list ===*/
	} );
};
// }}}

// {{{ get_user_logout ( req: ILRequest, cback: LCBack = null ): Promise<number>
/**
 * Logs out the current user
 *

 *
 */
export const get_user_logout = ( req: ILRequest, cback: LCback = null ): Promise<number> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start get_user_logout ===*/
		if ( !req.user ) return cback ? cback( null, false ) : resolve( false as any );

		const [ key, sess_id ] = await session_id( req, null );

		await session_del( req, key );

		return cback ? cback( null, true ) : resolve( true as any );
		/*=== d2r_end get_user_logout ===*/
	} );
};
// }}}

// {{{ get_user_me ( req: ILRequest, cback: LCBack = null ): Promise<User>
/**
 * Returns all the data of the currently logged user
 *

 *
 */
export const get_user_me = ( req: ILRequest, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start get_user_me ===*/
		const err = { message: _( 'User not found' ) };
		const u = await user_get( req.user?.id );

		if ( !u ) return cback ? cback( err ) : reject( err );

		await _addresses_add( req, u );

		keys_filter( u, UserKeys );

		return cback ? cback( null, u ) : resolve( u );
		/*=== d2r_end get_user_me ===*/
	} );
};
// }}}

// {{{ post_user_perms_set ( req: ILRequest, id_user: string, perms: UserPerms, cback: LCBack = null ): Promise<boolean>
/**
 * Sets the user permissions
 *
 * @param id_user - The user id [req]
 * @param perms - A JSON of `UserPerms` structure [req]
 *
 */
export const post_user_perms_set = ( req: ILRequest, id_user: string, perms: UserPerms, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_perms_set ===*/
		const user = await user_get( id_user );
		const err = { message: _( 'User not found' ) };

		if ( !user ) return cback ? cback( err ) : reject( err );

		user.perms = perms as any;
		await collection_add( _coll_users, user );

		return cback ? cback( null, true ) : resolve( true );
		/*=== d2r_end post_user_perms_set ===*/
	} );
};
// }}}

// {{{ post_user_info_add ( req: ILRequest, key: string, data: any, cback: LCBack = null ): Promise<boolean>
/**
 * Adds more data to the user in the extra field
 *
 * @param key - The main key. [req]
 * @param data - The new data to be added [req]
 *
 */
export const post_user_info_add = ( req: ILRequest, key: string, data: any, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start post_user_info_add ===*/
		const u = await user_get( req.user.id );

		if ( key ) u.extra[ key ] = data;

		await collection_add( _coll_users, u );

		return cback ? cback( null, 1 ) : resolve( 1 as any );
		/*=== d2r_end post_user_info_add ===*/
	} );
};
// }}}

// {{{ delete_user_info_del ( req: ILRequest, key: string, cback: LCBack = null ): Promise<boolean>
/**
 * Deletes a key from extra field
 *
 * @param key - The main key. [req]
 *
 */
export const delete_user_info_del = ( req: ILRequest, key: string, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start delete_user_info_del ===*/
		const u = await user_get( req.user.id );

		u.extra[ key ] = '__@@_invalid_@@__';

		await collection_add( _coll_users, u );

		return cback ? cback( null, true ) : resolve( true );
		/*=== d2r_end delete_user_info_del ===*/
	} );
};
// }}}

// {{{ patch_user_profile ( req: ILRequest, name?: string, lastname?: string, phone?: string, email?: string, addr_street?: string, addr_nr?: string, addr_zip?: string, addr_city?: string, addr_state?: string, addr_country?: string, facebook?: string, twitter?: string, linkedin?: string, instagram?: string, website?: string, cback: LCBack = null ): Promise<User>
/**
 * Changes data to the user profile
 *
 * @param name -  [opt]
 * @param lastname -  [opt]
 * @param phone -  [opt]
 * @param email -  [opt]
 * @param addr_street -  [opt]
 * @param addr_nr -  [opt]
 * @param addr_zip -  [opt]
 * @param addr_city -  [opt]
 * @param addr_state -  [opt]
 * @param addr_country -  [opt]
 * @param facebook -  [opt]
 * @param twitter -  [opt]
 * @param linkedin -  [opt]
 * @param instagram -  [opt]
 * @param website -  [opt]
 *
 */
export const patch_user_profile = ( req: ILRequest, name?: string, lastname?: string, phone?: string, email?: string, addr_street?: string, addr_nr?: string, addr_zip?: string, addr_city?: string, addr_state?: string, addr_country?: string, facebook?: string, twitter?: string, linkedin?: string, instagram?: string, website?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start patch_user_profile ===*/
		const err = { message: _( 'User not found' ) };
		let u: User = await user_get( req.user.id );

		if ( !u ) return cback ? cback( err ) : reject( err );

		u = { ...u, ...keys_valid( { name, lastname, phone, facebook, twitter, linkedin, instagram, website } ) };

		await collection_add( _coll_users, u );
		await address_add( req, u.id, addr_street, addr_nr, "home", "home", addr_city, addr_zip, addr_state, addr_country, null, null, null, null, null, null, true );

		await _addresses_add( req, u );

		return cback ? cback( null, u ) : resolve( u );
		/*=== d2r_end patch_user_profile ===*/
	} );
};
// }}}

// {{{ get_user_test_create ( req: ILRequest, cback: LCBack = null ): Promise<User>
/**
 * Creates a demo user
 *

 *
 */
export const get_user_test_create = ( req: ILRequest, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start get_user_test_create ===*/
		const user = { "email": "mario.rossi@gmail.com", "password": sha512( "Ciao123!" ), "enabled": true, "created": Date(), name: "Mario", lastname: "Rossi" };
		await collection_add( _coll_users, user );

		return cback ? cback( null, user ) : resolve( user as any );
		/*=== d2r_end get_user_test_create ===*/
	} );
};
// }}}

// {{{ patch_user_change_password ( req: ILRequest, old_password: string, new_password: string, recaptcha: string, cback: LCBack = null ): Promise<boolean>
/**
 * Changes the user password
 *
 * @param old_password -  [req]
 * @param new_password -  [req]
 * @param recaptcha -  [req]
 *
 */
export const patch_user_change_password = ( req: ILRequest, old_password: string, new_password: string, recaptcha: string, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start patch_user_change_password ===*/
		const err = { message: _( 'Passwords not matching' ) };

		const valid = await _recaptcha_check( req, recaptcha, err );

		if ( !valid ) return cback ? cback( err ) : reject( err );

		let user: User = await user_get( req.user.id );

		if ( !_password_check( req, old_password, user, err ) )
			return cback ? cback( err ) : reject( err );

		if ( !_valid_password( new_password, err, req.cfg ) )
			return cback ? cback( err ) : reject( err );

		user.password = sha512( new_password, false );

		await collection_add( _coll_users, user, false );

		return cback ? cback( null, true ) : resolve( true );
		/*=== d2r_end patch_user_change_password ===*/
	} );
};
// }}}

// {{{ patch_user_set_bio ( req: ILRequest, tagline: string, bio: string, cback: LCBack = null ): Promise<User>
/**
 * Creates / update users bio
 *
 * @param tagline -  [None]
 * @param bio -  [None]
 *
 */
export const patch_user_set_bio = ( req: ILRequest, tagline: string, bio: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start patch_user_set_bio ===*/
		let user: User = await user_get( req.user.id );

		if ( tagline ) user.tagline = tagline;
		if ( bio ) user.bio = bio;

		user = await collection_add( _coll_users, user, false, UserKeys );

		return cback ? cback( null, user ) : resolve( user );
		/*=== d2r_end patch_user_set_bio ===*/
	} );
};
// }}}

// {{{ patch_user_set_billing ( req: ILRequest, address: string, nr: string, name?: string, city?: string, zip?: string, state?: string, country?: string, company_name?: string, fiscal_code?: string, vat_number?: string, sdi?: string, pec?: string, cback: LCBack = null ): Promise<User>
/**
 * Creates / update user billing info
 *
 * @param address - The street address [req]
 * @param nr - The street address number [req]
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
 */
export const patch_user_set_billing = ( req: ILRequest, address: string, nr: string, name?: string, city?: string, zip?: string, state?: string, country?: string, company_name?: string, fiscal_code?: string, vat_number?: string, sdi?: string, pec?: string, cback: LCback = null ): Promise<User> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start patch_user_set_billing ===*/
		await address_add( req, req.user.id, address, nr, 'Invoice info', 'invoice', city, zip, state, country, company_name, fiscal_code, vat_number, sdi, pec, null, true );

		const user: User = await user_get( req.user.id );
		await _addresses_add( req, user );

		keys_filter( user, UserKeys );

		return cback ? cback( null, user ) : resolve( user );
		/*=== d2r_end patch_user_set_billing ===*/
	} );
};
// }}}


/**
 * Initializes user module database
 *
 * @param liwe - LiWE full config [req]
 *
 */
export const user_db_init = ( liwe: ILiWE, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		_liwe = liwe;

		_coll_user_facerecs = await collection_init( liwe.db, COLL_USER_FACERECS, [
			{ type: "persistent", fields: [ "id" ], unique: true },
			{ type: "persistent", fields: [ "domain" ], unique: false },
			{ type: "persistent", fields: [ "id_user" ], unique: false },
			{ type: "persistent", fields: [ "id_upload" ], unique: true },
		], { drop: false } );

		_coll_users = await collection_init( liwe.db, COLL_USERS, [
			{ type: "persistent", fields: [ "id" ], unique: true },
			{ type: "persistent", fields: [ "domain" ], unique: false },
			{ type: "persistent", fields: [ "email" ], unique: true },
			{ type: "persistent", fields: [ "enabled" ], unique: false },
			{ type: "persistent", fields: [ "tags[*]" ], unique: false },
			{ type: "persistent", fields: [ "id_upload" ], unique: false },
			{ type: "persistent", fields: [ "deleted" ], unique: false },
		], { drop: false } );

		/*=== d2r_start user_db_init ===*/

		// Create system users
		await Promise.all( _liwe.cfg.user.users.map( async ( u: any ) => {
			u.password = sha512( u.password );
			u.id = mkid( 'user' );
			delete u.u_id;
			const ck = await collection_find_one( liwe.db, `FOR u IN ${ COLL_USERS } FILTER u.email == @email RETURN u.id`, { email: u.email } );
			if ( ck ) return true;

			return collection_add( _coll_users, u );
		} ) );

		return cback ? cback( null, _liwe.db ) : resolve( _liwe.db );
		/*=== d2r_end user_db_init ===*/
	} );
};

/**
 * Creates a new session for the User
 *
 * @param req - The ILRequest [req]
 * @param user - The user to create the session to [req]
 *
 */
export const user_session_create = ( req: ILRequest, user: User, cback: LCback = null ): Promise<string> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start user_session_create ===*/
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
		/*=== d2r_end user_session_create ===*/
	} );
};

/**
 * Returns a user session by the given Token
 *
 * @param req - The ILRequest [req]
 * @param tok - The JSON Web Token to decode [req]
 *
 */
export const user_session_get = ( req: ILRequest, tok: string, cback: LCback = null ): Promise<any> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start user_session_get ===*/
		const payload = jwt_decrypt( tok, _liwe.cfg.security.secret );
		const err = { message: _( 'Session expired' ) };

		if ( !payload ) return cback ? cback( err ) : reject( err );

		const [ key, sess_id ] = await session_id( req, payload );

		const data = await session_get( req, key );

		err.message = _( 'Session not found' );
		if ( !data ) return cback ? cback( err ) : reject( err );

		return cback ? cback( null, data ) : resolve( data );
		/*=== d2r_end user_session_get ===*/
	} );
};

/**
 * Deletes a session of one user
 *
 * @param req - The ILRequest [req]
 * @param key - The Session key [req]
 *
 */
export const user_session_del = ( req: ILRequest, key: string, cback: LCback = null ): Promise<boolean> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start user_session_del ===*/
		const s = "FOR el IN sessions FILTER el.key == @key REMOVE el IN sessions";
		await _liwe.db.query( s, { key } );

		return cback ? cback( null, true ) : resolve( true );
		/*=== d2r_end user_session_del ===*/
	} );
};

/**
 * Gets all Face Rec binded to a user
 *
 * @param req - The ILRequest [req]
 * @param id_user - ID User [req]
 *
 */
export const user_facerec_get = ( req: ILRequest, id_user: string, cback: LCback = null ): Promise<UserFaceRec[]> => {
	return new Promise( async ( resolve, reject ) => {
		/*=== d2r_start user_facerec_get ===*/
		const faces: UserFaceRec[] = await collection_find_all_dict( req.db, COLL_USER_FACERECS, { id_user }, UserFaceRecKeys );

		return cback ? cback( null, faces ) : resolve( faces );
		/*=== d2r_end user_facerec_get ===*/
	} );
};
