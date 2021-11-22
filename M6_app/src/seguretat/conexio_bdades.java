package seguretat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class conexio_bdades {

	// Atributs de la connexi�
		private static Connection conn = null;
		private String driver;
		private String url;
		private String usuario;
		private String password;

		// Constructor de la connexi� per accedir als m�todes
		public conexio_bdades() {

			this.url = "jdbc:postgresql://192.168.1.37:5432/Projecte1";
			this.driver = "org.postgresql.Driver";
			this.usuario = "odoo";
			this.password = "odoo";

			try {
				Class.forName(driver);
				conn = DriverManager.getConnection(url, usuario, password);
			} catch (ClassNotFoundException | SQLException e) {
				e.printStackTrace();
			}
		}
		// M�tode per realitzar la connexi�
		public static Connection getConnection() {

			if (conn == null) {
				new conexio_bdades();
			}

			return conn;
		} // Fin getConnection
	}
