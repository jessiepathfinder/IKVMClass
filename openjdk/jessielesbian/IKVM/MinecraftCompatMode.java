package jessielesbian.IKVM;
public final class MinecraftCompatMode{
	public static void Enable(){
		java.net.Socket.MinecraftCompatMode = true;
		java.net.DatagramSocket.MinecraftCompatMode = true;
	}
}