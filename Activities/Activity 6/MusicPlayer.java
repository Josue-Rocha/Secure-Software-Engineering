// javac MusicPlayer.java --release 8 && jar cvf MusicPlayer.jar *.class && rm *.class
public class MusicPlayer {
    public static void main(String[] args) {
        Player p;

        // choose type based on command-line argument length
        if (args.length == 0) {
            p = new GuitarPlayer();
        } else if (args.length == 1) {
            p = new PianoPlayer();
        } else {
            p = new DrumPlayer();
        }

        // polymorphic method call
        p.play();
    }
}

interface Player {
    void play();
}

class GuitarPlayer implements Player {
    public void play() {
        System.out.println("Strumming chords on the guitar 🎸");
    }
}

class PianoPlayer implements Player {
    public void play() {
        System.out.println("Playing a soft melody on the piano 🎹");
    }
}

class DrumPlayer implements Player {
    public void play() {
        System.out.println("Beating rhythm on the drums 🥁");
    }
}