import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.ipa.callgraph.*;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.ipa.slicer.*;
import com.ibm.wala.ipa.slicer.Slicer.ControlDependenceOptions;
import com.ibm.wala.ipa.slicer.Slicer.DataDependenceOptions;
import com.ibm.wala.ssa.*;
import com.ibm.wala.types.*;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.collections.HashSetFactory;
import com.ibm.wala.util.config.FileOfClasses;
import com.ibm.wala.util.graph.Graph;
import com.ibm.wala.util.graph.GraphSlicer;
import com.ibm.wala.util.graph.traverse.BFSPathFinder;
import com.ibm.wala.util.strings.Atom;
import viz.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarFile;

import static com.ibm.wala.types.TypeReference.findOrCreate;


public class ExampleL14 {

    public static void main(String[] args) throws IOException, ClassHierarchyException, CancelException {
        //Create the analysis scope
        AnalysisScope scope = AnalysisScope.createJavaAnalysisScope();
        //String jarFilePath = ExampleL14.class.getResource("Example4.jar").getPath();
        String jarFilePath = MusicPlayer.class.getResource("MusicPlayer.jar").getPath();
        scope.addToScope(ClassLoaderReference.Application, new JarFile(jarFilePath));
        //String jrePath = ExampleL14.class.getResource("jdk-17.0.1/rt.jar").getPath();
        String jrePath = MusicPlayer.class.getResource("jdk-17.0.1/rt.jar").getPath();
        scope.addToScope(ClassLoaderReference.Primordial, new JarFile(jrePath));
        //String exFilePath = ExampleL14.class.getResource("Java60RegressionExclusions.txt").getPath();
        String exFilePath = MusicPlayer.class.getResource("Java60RegressionExclusions.txt").getPath();
        scope.setExclusions(new FileOfClasses(new FileInputStream(exFilePath)));

        // Create the class hierarchy
        IClassHierarchy classHierarchy = ClassHierarchyFactory.make(scope);

        // Create the 2-CFA call graph
        AnalysisOptions options = new AnalysisOptions();
        Iterable<Entrypoint> entrypoints = Util.makeMainEntrypoints(scope, classHierarchy);
        options.setEntrypoints(entrypoints);
        SSAPropagationCallGraphBuilder builder = Util.makeNCFABuilder(2, options, new AnalysisCacheImpl(), classHierarchy, scope);
        CallGraph callGraph = builder.makeCallGraph(options, null);
        ExampleL13.printCallGraph(callGraph, "2-CFA");