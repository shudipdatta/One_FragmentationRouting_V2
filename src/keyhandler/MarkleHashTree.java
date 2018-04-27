package keyhandler;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import routing.FragmentationRouter;

public class MarkleHashTree {

	public class TreeNode {
		public TreeNode parent;
		public TreeNode sibling;
		public byte[] hash;
		public ArrayList<TreeNode> children;
		
		public TreeNode(TreeNode parent, TreeNode sibling) {
			this.parent = parent;
			this.sibling = sibling;
			this.hash = new byte[AEScrypto.hashLenght];
			this.children = new ArrayList<TreeNode>();
		}
	}
	
	public FragmentationRouter router;
	public int numOfLeaf;
	public TreeNode root;
	public ArrayList<TreeNode> leafNodes;
	
	public MarkleHashTree(FragmentationRouter router) {
		this.leafNodes = new ArrayList<TreeNode>();
		this.router = router;
		this.numOfLeaf = router.keyShareN;
		
		this.root = new TreeNode(null, null);
		this.BuildTree((int) (Math.log(numOfLeaf)/Math.log(2)), this.root);
	}
	
	public void BuildTree(int height, TreeNode parent) {
		TreeNode childLeft = new TreeNode(parent, null);
		TreeNode childRight = new TreeNode(parent, null);
		childLeft.sibling = childRight;
		childRight.sibling = childLeft;
		parent.children.add(childLeft);
		parent.children.add(childRight);
		
		if(height == 1) {
			leafNodes.add(childLeft);
			leafNodes.add(childRight);
		}
		else {
			BuildTree(height-1, childLeft);
			BuildTree(height-1, childRight);
		}
	}
	
	public byte[] CalculateHash(TreeNode parent) {
		if(parent.children.size() > 0) {
			byte[] hashLeft = CalculateHash(parent.children.get(0));
			byte[] hashRight = CalculateHash(parent.children.get(1));
			
			byte[] concatedHash = new byte[2 * AEScrypto.hashLenght];
			System.arraycopy(hashLeft, 0, concatedHash, 0, AEScrypto.hashLenght);
			System.arraycopy(hashRight, 0, concatedHash, AEScrypto.hashLenght, AEScrypto.hashLenght);
			
			byte[] hash;
			try {
				hash = router.aes.Hash(concatedHash);
			} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				hash = new byte[0];
			}
			System.arraycopy(hash, 0, parent.hash, 0, AEScrypto.hashLenght);
			return hash;
		}
		else {
			return parent.hash;
		}
	}
}
