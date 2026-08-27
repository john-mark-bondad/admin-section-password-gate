<?php
/**
 * Plugin Name: Admin Section Password Gate
 * Plugin URI:  https://github.com/john-mark-bondad/admin-section-password-gate
 * Description: Puts a second password in front of chosen wp-admin pages (and their REST endpoints), even if the target plugin has no lock of its own.
 * Version:     1.0.0
 * Author:      John Mark Bondad
 * Author URI:  https://github.com/john-mark-bondad/
 *
 * SETUP:
 * 1. Generate a hash: php -r "echo password_hash('YOUR-PASSWORD', PASSWORD_DEFAULT);"
 *    Paste the result into $password_hash below.
 * 2. Add the admin page slug(s) you want locked to $protected_page_slugs
 *    (find it in the URL: admin.php?page=THIS-PART).
 * 3. Optional: add REST namespaces to $protected_rest_namespaces if the
 *    plugin loads data via REST (check DevTools → Network for /wp-json/...).
 * 4. Upload this file to wp-content/mu-plugins/ — no activation needed.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Admin_Section_Password_Gate {

	/* ---------------- CONFIG — edit these ---------------- */

	private $password_hash = '$2y$10$REPLACE_WITH_YOUR_OWN_HASH';

	private $protected_page_slugs = array(
		'snippets',
		'edit-snippet',
		'add-snippet',
		'import-code-snippets',
		'snippets-settings',
	);

	private $protected_rest_namespaces = array(
		'code-snippets/v1',
	);

	private $max_attempts    = 5;  // failed tries before lockout
	private $lockout_minutes = 15;
	private $unlocked_hours  = 24; // how long a successful unlock lasts

	/* ---------------- Internals ---------------- */

	private $cookie_name  = 'admin_section_gate_token';
	private $nonce_action = 'admin_section_gate_unlock';

	public function __construct() {
		add_action( 'admin_init', array( $this, 'maybe_gate_admin_page' ) );

		if ( ! empty( $this->protected_rest_namespaces ) ) {
			add_filter( 'rest_pre_dispatch', array( $this, 'maybe_gate_rest_request' ), 10, 3 );
		}
	}

	private function is_protected_admin_page() {
		if ( ! is_admin() || empty( $_GET['page'] ) ) {
			return false;
		}
		$page = sanitize_text_field( wp_unslash( $_GET['page'] ) );
		return in_array( $page, $this->protected_page_slugs, true );
	}

	private function is_protected_rest_route( $request ) {
		$route = ltrim( $request->get_route(), '/' );
		foreach ( $this->protected_rest_namespaces as $namespace ) {
			if ( 0 === strpos( $route, $namespace ) ) {
				return true;
			}
		}
		return false;
	}

	// Per-user, per-day unlock token — expires daily even if the cookie survives.
	private function make_token() {
		return hash_hmac(
			'sha256',
			get_current_user_id() . $this->password_hash . gmdate( 'Y-m-d' ),
			wp_salt()
		);
	}

	private function is_unlocked() {
		if ( empty( $_COOKIE[ $this->cookie_name ] ) ) {
			return false;
		}
		$submitted = sanitize_text_field( wp_unslash( $_COOKIE[ $this->cookie_name ] ) );
		return hash_equals( $this->make_token(), $submitted );
	}

	/* ---------------- Rate limiting (via transients) ---------------- */

	private function attempts_key() {
		return 'asg_attempts_' . get_current_user_id();
	}

	private function lockout_key() {
		return 'asg_lockout_' . get_current_user_id();
	}

	private function get_lockout_until() {
		$until = get_transient( $this->lockout_key() );
		return $until ? (int) $until : false;
	}

	private function record_failed_attempt() {
		$attempts = (int) get_transient( $this->attempts_key() );
		$attempts++;

		if ( $attempts >= $this->max_attempts ) {
			$until = time() + ( $this->lockout_minutes * MINUTE_IN_SECONDS );
			set_transient( $this->lockout_key(), $until, $this->lockout_minutes * MINUTE_IN_SECONDS );
			delete_transient( $this->attempts_key() );
		} else {
			set_transient( $this->attempts_key(), $attempts, $this->lockout_minutes * MINUTE_IN_SECONDS );
		}
	}

	private function clear_attempts() {
		delete_transient( $this->attempts_key() );
		delete_transient( $this->lockout_key() );
	}

	/* ---------------- Gates ---------------- */

	public function maybe_gate_admin_page() {
		if ( ! $this->is_protected_admin_page() ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( $this->is_unlocked() ) {
			return;
		}

		$lockout_until = $this->get_lockout_until();
		$error         = '';

		if ( $lockout_until ) {
			$minutes_left = (int) ceil( ( $lockout_until - time() ) / MINUTE_IN_SECONDS );
			$error        = sprintf(
				'Too many incorrect attempts. Try again in %d minute%s.',
				max( 1, $minutes_left ),
				1 === $minutes_left ? '' : 's'
			);
		} elseif ( isset( $_POST['asg_password'] ) && check_admin_referer( $this->nonce_action ) ) {
			$submitted = (string) wp_unslash( $_POST['asg_password'] );

			if ( password_verify( $submitted, $this->password_hash ) ) {
				$this->clear_attempts();
				setcookie(
					$this->cookie_name,
					$this->make_token(),
					time() + ( $this->unlocked_hours * HOUR_IN_SECONDS ),
					ADMIN_COOKIE_PATH,
					COOKIE_DOMAIN,
					is_ssl(),
					true
				);
				wp_safe_redirect( esc_url_raw( $_SERVER['REQUEST_URI'] ) );
				exit;
			}

			$this->record_failed_attempt();
			$error = 'Incorrect password.';
		}

		$this->render_form( $error, (bool) $lockout_until );
		exit;
	}

	public function maybe_gate_rest_request( $result, $server, $request ) {
		if ( ! $this->is_protected_rest_route( $request ) ) {
			return $result;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return $result;
		}
		if ( $this->is_unlocked() ) {
			return $result;
		}

		return new WP_Error(
			'admin_section_gate_locked',
			'This section is locked. Please unlock it from its admin page first.',
			array( 'status' => 401 )
		);
	}

	/* ---------------- Output ---------------- */

	private function render_form( $error, $is_locked_out ) {
		?>
		<!DOCTYPE html>
		<html <?php language_attributes(); ?>>
		<head>
			<meta charset="<?php bloginfo( 'charset' ); ?>">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>Locked</title>
			<style>
				html, body { background: transparent; height: 100%; margin: 0; }
				body {
					font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
					display: flex; align-items: center; justify-content: center;
				}
				.box {
					background: rgba(255, 255, 255, 0.9);
					backdrop-filter: blur(4px);
					padding: 32px; border-radius: 6px;
					box-shadow: 0 1px 3px rgba(0, 0, 0, .13);
					width: 320px;
				}
				h2 { margin-top: 0; font-size: 18px; }
				input[type="password"] {
					width: 100%; box-sizing: border-box; padding: 8px; margin: 12px 0;
					border: 1px solid #8c8f94; border-radius: 4px;
				}
				.buttons { display: flex; gap: 8px; }
				button, .cancel-link {
					flex: 1; padding: 8px; border-radius: 4px; font-size: 14px;
					text-align: center; text-decoration: none; cursor: pointer; box-sizing: border-box;
				}
				button { background: #2271b1; color: #fff; border: 0; }
				button:hover { background: #135e96; }
				button:disabled { background: #8c8f94; cursor: not-allowed; }
				.cancel-link { background: #f0f0f1; color: #1d2327; border: 1px solid #8c8f94; }
				.cancel-link:hover { background: #e0e0e1; }
				.error { color: #d63638; font-size: 13px; }
			</style>
		</head>
		<body>
			<div class="box">
				<h2>Enter password to continue</h2>
				<?php if ( $error ) : ?>
					<p class="error"><?php echo esc_html( $error ); ?></p>
				<?php endif; ?>
				<form method="post">
					<?php wp_nonce_field( $this->nonce_action ); ?>
					<input type="password" name="asg_password" autofocus required <?php disabled( $is_locked_out ); ?>>
					<div class="buttons">
						<button type="submit" <?php disabled( $is_locked_out ); ?>>Unlock</button>
						<a class="cancel-link" href="<?php echo esc_url( admin_url() ); ?>">Cancel</a>
					</div>
				</form>
			</div>
		</body>
		</html>
		<?php
	}
}

new Admin_Section_Password_Gate();
