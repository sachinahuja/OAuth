package moofwd.auth;

public abstract class OutputUtils {

	public static final String REDB = "\033[1;41m";
	public static final String REDF = "\033[31m";
	public static final String GREENB = "\033[1;42m";
	public static final String GREENF = "\033[1;32m";
	public static final String YELLOWB = "\033[1;43m";
	public static final String YELLOWF = "\033[1;33m";
	public static final String BLUEB = "\033[1;44m";
	public static final String BLUEF = "\033[1;34m";
	public static final String MAGENTAB = "\033[1;45m";
	public static final String MAGENTAF = "\033[1;35m";
	public static final String CYANB = "\033[1;46m";
	public static final String CYANF = "\033[1;36m";
	public static final String WHITEB = "\033[1;47m";
	public static final String WHITEF = "\033[1;37m";
	public static final String RESET = "\033[0m";
	public static final String NL = "\n";
	
	public static final String MOOFWD_VM = "again";
	
	
	public static final String cmd_check_vbox 				= "VBoxManage --version";
	public static final String cmd_mount_vbox_image			= "hdid vbox.dmg";
	public static final String cmd_install_vbox				= "sudo -S installer -pkg /Volumes/VirtualBox/VirtualBox.mpkg -target /";
	public static final String cmd_start_vb_srv			 	= "vboxwebsrv &";
	public static final String cmd_bash 					= "/bin/bash";
	public static final String cmd_c						= "-c";
	
	//vbox stuff
	public static final String vbox_url = "http://localhost:18083"; 
	public static final String vbox_user = "test"; 
	public static final String vbox_passwd = "test";
	
	private static int prev_length;
	private static int ctr = 0;
	
	public static void say(String s){
		//System.out.println(s);
		System.out.print(NL+RESET+MAGENTAF+s+RESET); //remove trailing reset later
		prev_length = s.length();
	}
	
	public static void shout(String s){
		//System.out.println(s);
		System.out.print(NL+RESET+REDF+s+RESET);
		prev_length = s.length();
	}
	
	public static void more(String s){
		System.out.print(s);
		prev_length = s.length();
	}
	
	public static void overwrite(String s){
		for (ctr=0;ctr<prev_length;ctr++){
			System.out.print("\b");
		}
		more(s);
	}
}
